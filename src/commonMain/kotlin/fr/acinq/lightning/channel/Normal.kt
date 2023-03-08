package fr.acinq.lightning.channel

import fr.acinq.lightning.Feature
import fr.acinq.lightning.Features
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.blockchain.BITCOIN_FUNDING_DEPTHOK
import fr.acinq.lightning.blockchain.WatchConfirmed
import fr.acinq.lightning.blockchain.WatchEventConfirmed
import fr.acinq.lightning.blockchain.WatchEventSpent
import fr.acinq.lightning.channel.ChannelAction.ProcessCmdRes.SpliceFailure
import fr.acinq.lightning.router.Announcements
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.Either
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toMilliSatoshi
import fr.acinq.lightning.wire.*

data class Normal(
    override val commitments: Commitments,
    val shortChannelId: ShortChannelId,
    val buried: Boolean,
    val channelAnnouncement: ChannelAnnouncement?,
    val channelUpdate: ChannelUpdate,
    val remoteChannelUpdate: ChannelUpdate?,
    val localShutdown: Shutdown?,
    val remoteShutdown: Shutdown?,
    val closingFeerates: ClosingFeerates?,
    val spliceStatus: SpliceStatus = SpliceStatus.None
) : ChannelStateWithCommitments() {
    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when (cmd) {
            is ChannelCommand.ExecuteCommand -> {
                when (cmd.command) {
                    is CMD_ADD_HTLC -> {
                        if (localShutdown != null || remoteShutdown != null) {
                            // note: spec would allow us to keep sending new htlcs after having received their shutdown (and not sent ours)
                            // but we want to converge as fast as possible and they would probably not route them anyway
                            val error = NoMoreHtlcsClosingInProgress(channelId)
                            return handleCommandError(cmd.command, error, channelUpdate)
                        }
                        handleCommandResult(cmd.command, commitments.sendAdd(cmd.command, cmd.command.paymentId, currentBlockHeight.toLong()), cmd.command.commit)
                    }
                    is CMD_FULFILL_HTLC -> handleCommandResult(cmd.command, commitments.sendFulfill(cmd.command), cmd.command.commit)
                    is CMD_FAIL_HTLC -> handleCommandResult(cmd.command, commitments.sendFail(cmd.command, this.privateKey), cmd.command.commit)
                    is CMD_FAIL_MALFORMED_HTLC -> handleCommandResult(cmd.command, commitments.sendFailMalformed(cmd.command), cmd.command.commit)
                    is CMD_UPDATE_FEE -> handleCommandResult(cmd.command, commitments.sendFee(cmd.command), cmd.command.commit)
                    is CMD_SIGN -> when {
                        !commitments.changes.localHasChanges() -> {
                            logger.warning { "no changes to sign" }
                            Pair(this@Normal, listOf())
                        }
                        commitments.remoteNextCommitInfo is Either.Left -> {
                            logger.debug { "already in the process of signing, will sign again as soon as possible" }
                            Pair(this@Normal, listOf())
                        }
                        else -> when (val result = commitments.sendCommit(keyManager, logger)) {
                            is Either.Left -> handleCommandError(cmd.command, result.value, channelUpdate)
                            is Either.Right -> {
                                val commitments1 = result.value.first
                                val nextRemoteSpec = commitments1.latest.nextRemoteCommit!!.commit.spec
                                // we persist htlc data in order to be able to claim htlc outputs in case a revoked tx is published by our
                                // counterparty, so only htlcs above remote's dust_limit matter
                                val trimmedHtlcs = Transactions.trimOfferedHtlcs(commitments.params.remoteParams.dustLimit, nextRemoteSpec) + Transactions.trimReceivedHtlcs(commitments.params.remoteParams.dustLimit, nextRemoteSpec)
                                val htlcInfos = trimmedHtlcs.map { it.add }.map {
                                    logger.info { "adding paymentHash=${it.paymentHash} cltvExpiry=${it.cltvExpiry} to htlcs db for commitNumber=${commitments1.nextRemoteCommitIndex}" }
                                    ChannelAction.Storage.HtlcInfo(channelId, commitments1.nextRemoteCommitIndex, it.paymentHash, it.cltvExpiry)
                                }
                                val nextState = this@Normal.copy(commitments = commitments1)
                                val actions = buildList {
                                    add(ChannelAction.Storage.StoreHtlcInfos(htlcInfos))
                                    add(ChannelAction.Storage.StoreState(nextState))
                                    addAll(result.value.second.map { ChannelAction.Message.Send(it) })
                                }
                                Pair(nextState, actions)
                            }
                        }
                    }
                    is CMD_CLOSE -> {
                        val allowAnySegwit = Features.canUseFeature(commitments.params.localParams.features, commitments.params.remoteParams.features, Feature.ShutdownAnySegwit)
                        val localScriptPubkey = cmd.command.scriptPubKey ?: commitments.params.localParams.defaultFinalScriptPubKey
                        when {
                            localShutdown != null -> handleCommandError(cmd.command, ClosingAlreadyInProgress(channelId), channelUpdate)
                            commitments.changes.localHasUnsignedOutgoingHtlcs() -> handleCommandError(cmd.command, CannotCloseWithUnsignedOutgoingHtlcs(channelId), channelUpdate)
                            commitments.changes.localHasUnsignedOutgoingUpdateFee() -> handleCommandError(cmd.command, CannotCloseWithUnsignedOutgoingUpdateFee(channelId), channelUpdate)
                            !Helpers.Closing.isValidFinalScriptPubkey(localScriptPubkey, allowAnySegwit) -> handleCommandError(cmd.command, InvalidFinalScript(channelId), channelUpdate)
                            else -> {
                                val shutdown = Shutdown(channelId, localScriptPubkey)
                                val newState = this@Normal.copy(localShutdown = shutdown, closingFeerates = cmd.command.feerates)
                                val actions = listOf(ChannelAction.Storage.StoreState(newState), ChannelAction.Message.Send(shutdown))
                                Pair(newState, actions)
                            }
                        }
                    }
                    is CMD_FORCECLOSE -> handleLocalError(cmd, ForcedLocalCommit(channelId))
                    is CMD_BUMP_FUNDING_FEE -> unhandled(cmd)
                    is CMD_SPLICE -> when (spliceStatus) {
                        is SpliceStatus.None -> {
                            if (commitments.isIdle()) {
                                val fundingAmount = InteractiveTxParams.computeLocalContribution(
                                    isInitiator = true,
                                    commitment = commitments.active.first(),
                                    spliceInAmount = cmd.command.additionalLocalFunding,
                                    spliceOut = cmd.command.spliceOutputs,
                                    targetFeerate = cmd.command.feerate
                                )
                                if (fundingAmount < 0.sat) {
                                    logger.warning { "cannot do splice: insufficient funds" }
                                    Pair(this@Normal, listOf(SpliceFailure.InsufficientFunds))
                                } else if (cmd.command.spliceOut?.scriptPubKey?.let { Helpers.Closing.isValidFinalScriptPubkey(it, allowAnySegwit = true) } == false) {
                                    logger.warning { "cannot do splice: invalid splice-out script" }
                                    Pair(this@Normal, listOf(SpliceFailure.InvalidSpliceOutPubKeyScript))
                                } else {
                                    logger.info { "initiating splice with local.in.amount=${cmd.command.additionalLocalFunding} local.in.push=${cmd.command.pushAmount} out.amount=${cmd.command.spliceOut?.amount ?: 0.msat}" }
                                    val spliceInit = SpliceInit(
                                        channelId,
                                        fundingAmount = fundingAmount,
                                        lockTime = currentBlockHeight.toLong(),
                                        feerate = cmd.command.feerate,
                                        pushAmount = cmd.command.pushAmount
                                    )
                                    Pair(this@Normal.copy(spliceStatus = SpliceStatus.Requested(cmd.command, spliceInit)), listOf(ChannelAction.Message.Send(spliceInit)))
                                }
                            } else {
                                logger.warning { "cannot initiate splice, channel not idle" }
                                Pair(this@Normal, listOf(SpliceFailure.ChannelNotIdle))
                            }
                        }
                        else -> {
                            logger.warning { "cannot initiate splice, another splice is already in progress" }
                            Pair(this@Normal, listOf(SpliceFailure.SpliceAlreadyInProgress))
                        }
                    }
                }
            }
            is ChannelCommand.MessageReceived -> {
                when (cmd.message) {
                    is UpdateAddHtlc -> when (val result = commitments.receiveAdd(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> {
                            val newState = this@Normal.copy(commitments = result.value)
                            Pair(newState, listOf())
                        }
                    }
                    is UpdateFulfillHtlc -> when (val result = commitments.receiveFulfill(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> {
                            val (commitments1, paymentId, add) = result.value
                            val htlcResult = ChannelAction.HtlcResult.Fulfill.RemoteFulfill(cmd.message)
                            Pair(this@Normal.copy(commitments = commitments1), listOf(ChannelAction.ProcessCmdRes.AddSettledFulfill(paymentId, add, htlcResult)))
                        }
                    }
                    is UpdateFailHtlc -> when (val result = commitments.receiveFail(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> Pair(this@Normal.copy(commitments = result.value.first), listOf())
                    }
                    is UpdateFailMalformedHtlc -> when (val result = commitments.receiveFailMalformed(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> Pair(this@Normal.copy(commitments = result.value.first), listOf())
                    }
                    is UpdateFee -> when (val result = commitments.receiveFee(cmd.message, staticParams.nodeParams.onChainFeeConf.feerateTolerance)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> Pair(this@Normal.copy(commitments = result.value), listOf())
                    }
                    is CommitSig -> when (spliceStatus) {
                        is SpliceStatus.WaitForCommitSig -> {
                            val parentCommitment = commitments.active.first()
                            val firstCommitmentRes = Helpers.Funding.receiveFirstCommitSig(
                                keyManager, spliceStatus.fundingParams, commitments.params.localParams, commitments.params.remoteParams,
                                fundingTxIndex = parentCommitment.fundingTxIndex + 1, fundingTx = spliceStatus.fundingTx,
                                commitmentIndex = parentCommitment.localCommit.index, parentCommitment.remoteCommit.remotePerCommitmentPoint,
                                spliceStatus.commitTxs, remoteCommitSig = cmd.message,
                                currentBlockHeight.toLong()
                            )
                            when (firstCommitmentRes) {
                                Helpers.Funding.InvalidRemoteCommitSig -> {
                                    logger.warning { "splice attempt failed: invalid commit_sig" }
                                    Pair(
                                        this@Normal.copy(spliceStatus = SpliceStatus.Aborted),
                                        listOf(ChannelAction.Message.Send(TxAbort(channelId, InvalidCommitmentSignature(channelId, spliceStatus.commitTxs.localCommitTx.tx.txid).message)))
                                    )
                                }
                                Helpers.Funding.FundingSigFailure -> {
                                    logger.warning { "could not sign splice funding tx" }
                                    Pair(this@Normal.copy(spliceStatus = SpliceStatus.Aborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, ChannelFundingError(channelId).message))))
                                }
                                is Helpers.Funding.FirstCommitment -> {
                                    val (signedFundingTx, commitment) = firstCommitmentRes
                                    logger.info { "splice funding tx created with txId=${commitment.fundingTxId}. ${signedFundingTx.tx.localInputs.size} local inputs, ${signedFundingTx.tx.remoteInputs.size} remote inputs, ${signedFundingTx.tx.localOutputs.size} local outputs and ${signedFundingTx.tx.remoteOutputs.size} remote outputs" }
                                    // We watch for confirmation in all cases, to allow pruning outdated commitments when transactions confirm.
                                    val fundingMinDepth = Helpers.minDepthForFunding(staticParams.nodeParams, spliceStatus.fundingParams.fundingAmount)
                                    val watchConfirmed = WatchConfirmed(channelId, commitment.fundingTxId, commitment.commitInput.txOut.publicKeyScript, fundingMinDepth.toLong(), BITCOIN_FUNDING_DEPTHOK)
                                    val commitments = commitments.add(commitment)
                                    val nextState = this@Normal.copy(commitments = commitments, spliceStatus = SpliceStatus.None)
                                    val actions = listOf(
                                        ChannelAction.Blockchain.SendWatch(watchConfirmed),
                                        // We're not a liquidity provider, so we don't mind sending our signatures immediately.
                                        ChannelAction.Message.Send(signedFundingTx.localSigs),
                                        ChannelAction.Storage.StoreState(nextState)
                                    )
                                    Pair(nextState, actions)
                                }
                            }
                        }
                        // NB: in all other cases we process the commit_sig normally. We could do a full pattern matching on all splice statuses, but it would force us to handle
                        // corner cases like race condition between splice_init and a non-splice commit_sig
                        else -> {
                            when (val result = commitments.receiveCommit(listOf(cmd.message), keyManager, logger)) {
                                is Either.Left -> handleLocalError(cmd, result.value)
                                is Either.Right -> {
                                    val nextState = this@Normal.copy(commitments = result.value.first)
                                    val actions = mutableListOf<ChannelAction>()
                                    actions.add(ChannelAction.Message.Send(result.value.second))
                                    actions.add(ChannelAction.Storage.StoreState(nextState))
                                    if (result.value.first.changes.localHasChanges()) {
                                        actions.add(ChannelAction.Message.SendToSelf(CMD_SIGN))
                                    }
                                    Pair(nextState, actions)
                                }
                            }
                        }
                    }
                    is RevokeAndAck -> when (val result = commitments.receiveRevocation(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> {
                            val commitments1 = result.value.first
                            val actions = mutableListOf<ChannelAction>()
                            actions.addAll(result.value.second)
                            if (result.value.first.changes.localHasChanges()) {
                                actions.add(ChannelAction.Message.SendToSelf(CMD_SIGN))
                            }
                            val nextState = if (remoteShutdown != null && !commitments1.changes.localHasUnsignedOutgoingHtlcs()) {
                                // we were waiting for our pending htlcs to be signed before replying with our local shutdown
                                val localShutdown = Shutdown(channelId, commitments.params.localParams.defaultFinalScriptPubKey)
                                actions.add(ChannelAction.Message.Send(localShutdown))
                                if (commitments1.latest.remoteCommit.spec.htlcs.isNotEmpty()) {
                                    // we just signed htlcs that need to be resolved now
                                    ShuttingDown(commitments1, localShutdown, remoteShutdown, closingFeerates)
                                } else {
                                    logger.warning { "we have no htlcs but have not replied with our Shutdown yet, this should never happen" }
                                    val closingTxProposed = if (isInitiator) {
                                        val (closingTx, closingSigned) = Helpers.Closing.makeFirstClosingTx(
                                            keyManager,
                                            commitments1.latest,
                                            localShutdown.scriptPubKey.toByteArray(),
                                            remoteShutdown.scriptPubKey.toByteArray(),
                                            closingFeerates ?: ClosingFeerates(currentOnChainFeerates.mutualCloseFeerate),
                                        )
                                        listOf(listOf(ClosingTxProposed(closingTx, closingSigned)))
                                    } else {
                                        listOf(listOf())
                                    }
                                    Negotiating(commitments1, localShutdown, remoteShutdown, closingTxProposed, bestUnpublishedClosingTx = null, closingFeerates)
                                }
                            } else {
                                this@Normal.copy(commitments = commitments1)
                            }
                            actions.add(0, ChannelAction.Storage.StoreState(nextState))
                            Pair(nextState, actions)
                        }
                    }
                    is ChannelUpdate -> {
                        if (cmd.message.shortChannelId == shortChannelId && cmd.message.isRemote(staticParams.nodeParams.nodeId, staticParams.remoteNodeId)) {
                            val nextState = this@Normal.copy(remoteChannelUpdate = cmd.message)
                            Pair(nextState, listOf(ChannelAction.Storage.StoreState(nextState)))
                        } else {
                            Pair(this@Normal, listOf())
                        }
                    }
                    is Shutdown -> {
                        val allowAnySegwit = Features.canUseFeature(commitments.params.localParams.features, commitments.params.remoteParams.features, Feature.ShutdownAnySegwit)
                        // they have pending unsigned htlcs         => they violated the spec, close the channel
                        // they don't have pending unsigned htlcs
                        //    we have pending unsigned htlcs
                        //      we already sent a shutdown message  => spec violation (we can't send htlcs after having sent shutdown)
                        //      we did not send a shutdown message
                        //        we are ready to sign              => we stop sending further htlcs, we initiate a signature
                        //        we are waiting for a rev          => we stop sending further htlcs, we wait for their revocation, will resign immediately after, and then we will send our shutdown message
                        //    we have no pending unsigned htlcs
                        //      we already sent a shutdown message
                        //        there are pending signed changes  => send our shutdown message, go to SHUTDOWN
                        //        there are no changes              => send our shutdown message, go to NEGOTIATING
                        //      we did not send a shutdown message
                        //        there are pending signed changes  => go to SHUTDOWN
                        //        there are no changes              => go to NEGOTIATING
                        when {
                            !Helpers.Closing.isValidFinalScriptPubkey(cmd.message.scriptPubKey, allowAnySegwit) -> handleLocalError(cmd, InvalidFinalScript(channelId))
                            commitments.changes.remoteHasUnsignedOutgoingHtlcs() -> handleLocalError(cmd, CannotCloseWithUnsignedOutgoingHtlcs(channelId))
                            commitments.changes.remoteHasUnsignedOutgoingUpdateFee() -> handleLocalError(cmd, CannotCloseWithUnsignedOutgoingUpdateFee(channelId))
                            commitments.changes.localHasUnsignedOutgoingHtlcs() -> {
                                require(localShutdown == null) { "can't have pending unsigned outgoing htlcs after having sent Shutdown" }
                                // are we in the middle of a signature?
                                when (commitments.remoteNextCommitInfo) {
                                    is Either.Left -> {
                                        // we already have a signature in progress, will resign when we receive the revocation
                                        Pair(this@Normal.copy(remoteShutdown = cmd.message), listOf())
                                    }
                                    is Either.Right -> {
                                        // no, let's sign right away
                                        val newState = this@Normal.copy(remoteShutdown = cmd.message, commitments = commitments.copy(remoteChannelData = cmd.message.channelData))
                                        Pair(newState, listOf(ChannelAction.Message.SendToSelf(CMD_SIGN)))
                                    }
                                }
                            }
                            else -> {
                                // so we don't have any unsigned outgoing changes
                                val actions = mutableListOf<ChannelAction>()
                                val localShutdown = this@Normal.localShutdown ?: Shutdown(channelId, commitments.params.localParams.defaultFinalScriptPubKey)
                                if (this@Normal.localShutdown == null) actions.add(ChannelAction.Message.Send(localShutdown))
                                val commitments1 = commitments.copy(remoteChannelData = cmd.message.channelData)
                                when {
                                    commitments1.hasNoPendingHtlcsOrFeeUpdate() && commitments1.params.localParams.isInitiator -> {
                                        val (closingTx, closingSigned) = Helpers.Closing.makeFirstClosingTx(
                                            keyManager,
                                            commitments1.latest,
                                            localShutdown.scriptPubKey.toByteArray(),
                                            cmd.message.scriptPubKey.toByteArray(),
                                            closingFeerates ?: ClosingFeerates(currentOnChainFeerates.mutualCloseFeerate),
                                        )
                                        val nextState = Negotiating(
                                            commitments1,
                                            localShutdown,
                                            cmd.message,
                                            listOf(listOf(ClosingTxProposed(closingTx, closingSigned))),
                                            bestUnpublishedClosingTx = null,
                                            closingFeerates
                                        )
                                        actions.addAll(listOf(ChannelAction.Storage.StoreState(nextState), ChannelAction.Message.Send(closingSigned)))
                                        Pair(nextState, actions)
                                    }
                                    commitments1.hasNoPendingHtlcsOrFeeUpdate() -> {
                                        val nextState = Negotiating(commitments1, localShutdown, cmd.message, listOf(listOf()), null, closingFeerates)
                                        actions.add(ChannelAction.Storage.StoreState(nextState))
                                        Pair(nextState, actions)
                                    }
                                    else -> {
                                        // there are some pending changes, we need to wait for them to be settled (fail/fulfill htlcs and sign fee updates)
                                        val nextState = ShuttingDown(commitments1, localShutdown, cmd.message, closingFeerates)
                                        actions.add(ChannelAction.Storage.StoreState(nextState))
                                        Pair(nextState, actions)
                                    }
                                }
                            }
                        }
                    }
                    is SpliceInit -> when (spliceStatus) {
                        is SpliceStatus.None ->
                            if (commitments.isIdle()) {
                                logger.info { "accepting splice with remote.in.amount=${cmd.message.fundingAmount} remote.in.push=${cmd.message.pushAmount}" }
                                val parentCommitment = commitments.active.first()
                                val spliceAck = SpliceAck(
                                    channelId,
                                    fundingAmount = parentCommitment.localCommit.spec.toLocal.truncateToSatoshi(), // only remote contributes to the splice
                                    pushAmount = 0.msat
                                )
                                val fundingParams = InteractiveTxParams(
                                    channelId = channelId,
                                    isInitiator = false,
                                    localAmount = spliceAck.fundingAmount,
                                    remoteAmount = cmd.message.fundingAmount,
                                    sharedInput = SharedFundingInput.Multisig2of2(keyManager, commitments.params, parentCommitment),
                                    fundingPubkeyScript = parentCommitment.commitInput.txOut.publicKeyScript, // same pubkey script as before
                                    localOutputs = emptyList(),
                                    lockTime = currentBlockHeight.toLong(),
                                    dustLimit = commitments.params.localParams.dustLimit.max(commitments.params.remoteParams.dustLimit),
                                    targetFeerate = cmd.message.feerate
                                )
                                // as non-initiator we don't contribute to this splice for now
                                val toSend = emptyList<Either<InteractiveTxInput.Outgoing, InteractiveTxOutput.Outgoing>>()
                                val session = InteractiveTxSession(
                                    fundingParams,
                                    previousLocalBalance = parentCommitment.localCommit.spec.toLocal.truncateToSatoshi(),
                                    previousRemoteBalance = parentCommitment.localCommit.spec.toRemote.truncateToSatoshi(),
                                    toSend, previousTxs = emptyList()
                                )
                                val nextState = this@Normal.copy(spliceStatus = SpliceStatus.InProgress(session, localPushAmount = 0.msat, remotePushAmount = cmd.message.pushAmount, origins = cmd.message.channelOrigins))
                                Pair(nextState, listOf(ChannelAction.Message.Send(SpliceAck(channelId, fundingParams.localAmount))))
                            } else {
                                logger.info { "rejecting splice attempt: channel is not idle" }
                                Pair(this@Normal, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidSpliceChannelNotIdle(channelId).message))))
                            }
                        is SpliceStatus.Aborted -> {
                            logger.info { "rejecting splice attempt: our previous tx_abort was not acked" }
                            Pair(this@Normal, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidSpliceAbortNotAcked(channelId).message))))
                        }
                        else -> {
                            logger.info { "rejecting splice attempt: the current splice attempt must be completed or aborted first" }
                            Pair(this@Normal, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidSpliceAlreadyInProgress(channelId).message))))
                        }
                    }
                    is SpliceAck -> when (spliceStatus) {
                        is SpliceStatus.Requested -> {
                            logger.info { "our peer accepted our splice request and will contribute ${cmd.message.fundingAmount} to the funding transaction" }
                            val parentCommitment = commitments.active.first()
                            val sharedInput = SharedFundingInput.Multisig2of2(keyManager, commitments.params, parentCommitment)
                            val fundingParams = InteractiveTxParams(
                                channelId = channelId,
                                isInitiator = true,
                                localAmount = spliceStatus.spliceInit.fundingAmount,
                                remoteAmount = cmd.message.fundingAmount,
                                sharedInput = sharedInput,
                                fundingPubkeyScript = parentCommitment.commitInput.txOut.publicKeyScript, // same pubkey script as before
                                localOutputs = spliceStatus.command.spliceOutputs,
                                lockTime = currentBlockHeight.toLong(),
                                dustLimit = commitments.params.localParams.dustLimit.max(commitments.params.remoteParams.dustLimit),
                                targetFeerate = spliceStatus.spliceInit.feerate
                            )
                            when (val fundingContributions = FundingContributions.create(
                                params = fundingParams,
                                sharedUtxo = Pair(sharedInput, parentCommitment.fundingAmount),
                                walletUtxos = spliceStatus.command.spliceIn?.wallet?.confirmedUtxos ?: emptyList(),
                                localOutputs = spliceStatus.command.spliceOutputs,
                                changePubKey = null // we're spending every funds available TODO: check this
                            )) {
                                is Either.Left -> {
                                    logger.error { "could not create splice contributions: ${fundingContributions.value}" }
                                    Pair(Aborted, listOf(ChannelAction.Message.Send(Error(channelId, ChannelFundingError(channelId).message))))
                                }
                                is Either.Right -> {
                                    // The splice initiator always sends the first interactive-tx message.
                                    val (interactiveTxSession, interactiveTxAction) = InteractiveTxSession(
                                        fundingParams,
                                        previousLocalBalance = parentCommitment.localCommit.spec.toLocal.truncateToSatoshi(),
                                        previousRemoteBalance = parentCommitment.localCommit.spec.toRemote.truncateToSatoshi(),
                                        fundingContributions.value, previousTxs = emptyList()
                                    ).send()
                                    when (interactiveTxAction) {
                                        is InteractiveTxSessionAction.SendMessage -> {
                                            val nextState = this@Normal.copy(
                                                spliceStatus = SpliceStatus.InProgress(
                                                    interactiveTxSession,
                                                    localPushAmount = spliceStatus.spliceInit.pushAmount,
                                                    remotePushAmount = cmd.message.pushAmount,
                                                    origins = emptyList()
                                                )
                                            )
                                            Pair(nextState, listOf(ChannelAction.Message.Send(interactiveTxAction.msg)))
                                        }
                                        else -> {
                                            logger.error { "could not start interactive-tx session: $interactiveTxAction" }
                                            Pair(Aborted, listOf(ChannelAction.Message.Send(Error(channelId, ChannelFundingError(channelId).message))))
                                        }
                                    }
                                }
                            }
                        }
                        else -> {
                            logger.warning { "ignoring unexpected splice_ack" }
                            Pair(this@Normal, emptyList())
                        }
                    }
                    is InteractiveTxConstructionMessage -> when (spliceStatus) {
                        is SpliceStatus.InProgress -> {
                            val (interactiveTxSession, interactiveTxAction) = spliceStatus.spliceSession.receive(cmd.message)
                            when (interactiveTxAction) {
                                is InteractiveTxSessionAction.SendMessage -> Pair(this@Normal.copy(spliceStatus = spliceStatus.copy(spliceSession = interactiveTxSession)), listOf(ChannelAction.Message.Send(interactiveTxAction.msg)))
                                is InteractiveTxSessionAction.SignSharedTx -> {
                                    val parentCommitment = commitments.active.first()
                                    val commitTxRes = Helpers.Funding.makeCommitTxsWithoutHtlcs(
                                        keyManager, channelId,
                                        commitments.params.localParams, commitments.params.remoteParams,
                                        fundingAmount = interactiveTxSession.fundingParams.localAmount + interactiveTxSession.fundingParams.remoteAmount,
                                        toLocal = interactiveTxSession.fundingParams.localAmount.toMilliSatoshi() - spliceStatus.localPushAmount + spliceStatus.remotePushAmount,
                                        toRemote = interactiveTxSession.fundingParams.remoteAmount.toMilliSatoshi() - spliceStatus.remotePushAmount + spliceStatus.localPushAmount,
                                        commitTxFeerate = parentCommitment.localCommit.spec.feerate,
                                        fundingTxHash = interactiveTxAction.sharedTx.buildUnsignedTx().hash,
                                        fundingTxOutputIndex = interactiveTxAction.sharedOutputIndex,
                                        remotePerCommitmentPoint = parentCommitment.remoteCommit.remotePerCommitmentPoint,
                                        commitmentIndex = parentCommitment.localCommit.index
                                    )
                                    when (commitTxRes) {
                                        is Either.Left -> {
                                            logger.error(commitTxRes.value) { "cannot create post-splice commit tx" }
                                            handleLocalError(cmd, commitTxRes.value)
                                        }
                                        is Either.Right -> {
                                            val commitTxs = commitTxRes.value
                                            val localSigOfRemoteTx = keyManager.sign(commitTxs.remoteCommitTx, commitments.params.localParams.channelKeys(keyManager).fundingPrivateKey)
                                            val commitSig = CommitSig(channelId, localSigOfRemoteTx, listOf())
                                            val nextState = this@Normal.copy(spliceStatus = SpliceStatus.WaitForCommitSig(interactiveTxSession.fundingParams, interactiveTxAction.sharedTx, commitTxs, spliceStatus.origins))
                                            val actions = buildList {
                                                interactiveTxAction.txComplete?.let { add(ChannelAction.Message.Send(it)) }
                                                add(ChannelAction.Message.Send(commitSig))
                                            }
                                            Pair(nextState, actions)
                                        }
                                    }
                                }
                                is InteractiveTxSessionAction.RemoteFailure -> {
                                    logger.warning { "interactive-tx failed: $interactiveTxAction" }
                                    handleLocalError(cmd, DualFundingAborted(channelId, interactiveTxAction.toString()))
                                }
                            }
                        }
                        else -> {
                            logger.info { "ignoring unexpected interactive-tx message: ${cmd.message::class}" }
                            Pair(this@Normal, listOf(ChannelAction.Message.Send(Warning(channelId, UnexpectedInteractiveTxMessage(channelId, cmd.message).message))))
                        }
                    }
                    is TxSignatures -> when (commitments.latest.localFundingStatus) {
                        is LocalFundingStatus.UnconfirmedFundingTx -> when (commitments.latest.localFundingStatus.sharedTx) {
                            is PartiallySignedSharedTransaction -> when (val fullySignedTx = commitments.latest.localFundingStatus.sharedTx.addRemoteSigs(commitments.latest.localFundingStatus.fundingParams, cmd.message)) {
                                null -> {
                                    logger.warning { "received invalid remote funding signatures for txId=${cmd.message.txId}" }
                                    // The funding transaction may still confirm (since our peer should be able to generate valid signatures), so we cannot close the channel yet.
                                    Pair(this@Normal, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidFundingSignature(channelId, cmd.message.txId).message))))
                                }
                                else -> {
                                    when (val res = commitments.run { updateLocalFundingStatus(fullySignedTx.signedTx.txid, commitments.latest.localFundingStatus.copy(sharedTx = fullySignedTx)) }) {
                                        is Either.Left -> Pair(this@Normal, listOf())
                                        is Either.Right -> {
                                            logger.info { "received remote funding signatures, publishing fundingTxId=${fullySignedTx.signedTx.txid} fundingTxIndex=${commitments.latest.fundingTxIndex}" }
                                            val nextState = this@Normal.copy(commitments = res.value.first)
                                            val actions = buildList {
                                                if (staticParams.useZeroConf) {
                                                    logger.info { "channel is using 0-conf, sending splice_locked right away" }
                                                    val spliceLocked = SpliceLocked(channelId, fullySignedTx.txId)
                                                    add(ChannelAction.Message.Send(spliceLocked))
                                                }
                                                add(ChannelAction.Blockchain.PublishTx(fullySignedTx.signedTx))
                                                add(ChannelAction.Storage.StoreState(nextState))
                                            }
                                            Pair(nextState, actions)
                                        }
                                    }
                                }
                            }
                            is FullySignedSharedTransaction -> {
                                logger.info { "ignoring duplicate remote funding signatures" }
                                Pair(this@Normal, listOf())
                            }
                        }
                        is LocalFundingStatus.ConfirmedFundingTx -> {
                            logger.info { "ignoring funding signatures for txId=${cmd.message.txId}, transaction is already confirmed" }
                            Pair(this@Normal, listOf())
                        }
                    }
                    is SpliceLocked -> {
                        when (val res = commitments.run { updateRemoteFundingStatus(cmd.message.fundingTxid) }) {
                            is Either.Left -> Pair(this@Normal, emptyList())
                            is Either.Right -> {
                                val (commitments1, _) = res.value
                                val nextState = this@Normal.copy(commitments = commitments1)
                                Pair(nextState, listOf(ChannelAction.Storage.StoreState(nextState)))
                            }
                        }
                    }
                    is Error -> handleRemoteError(cmd.message)
                    else -> unhandled(cmd)
                }
            }
            is ChannelCommand.CheckHtlcTimeout -> checkHtlcTimeout()
            is ChannelCommand.WatchReceived -> when (val watch = cmd.watch) {
                is WatchEventConfirmed -> when (val res = acceptFundingTxConfirmed(watch)) {
                    is Either.Left -> Pair(this@Normal, listOf())
                    is Either.Right -> {
                        val (commitments1, _, actions) = res.value
                        val nextState = this@Normal.copy(commitments = commitments1)
                        Pair(nextState, actions + listOf(ChannelAction.Storage.StoreState(nextState)))
                    }
                }
                is WatchEventSpent -> handlePotentialForceClose(watch)
            }
            is ChannelCommand.Disconnected -> {
                // if we have pending unsigned outgoing htlcs, then we cancel them and advertise the fact that the channel is now disabled.
                val failedHtlcs = mutableListOf<ChannelAction>()
                val proposedHtlcs = commitments.changes.localChanges.proposed.filterIsInstance<UpdateAddHtlc>()
                if (proposedHtlcs.isNotEmpty()) {
                    logger.info { "updating channel_update announcement (reason=disabled)" }
                    val channelUpdate = Announcements.disableChannel(channelUpdate, staticParams.nodeParams.nodePrivateKey, staticParams.remoteNodeId)
                    proposedHtlcs.forEach { htlc ->
                        commitments.payments[htlc.id]?.let { paymentId ->
                            failedHtlcs.add(ChannelAction.ProcessCmdRes.AddSettledFail(paymentId, htlc, ChannelAction.HtlcResult.Fail.Disconnected(channelUpdate)))
                        } ?: logger.warning { "cannot find payment for $htlc" }
                    }
                }
                Pair(Offline(this@Normal), failedHtlcs)
            }
            else -> unhandled(cmd)
        }
    }

    override fun ChannelContext.handleLocalError(cmd: ChannelCommand, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "error on command ${cmd::class.simpleName} in state ${this@Normal::class.simpleName}" }
        val error = Error(channelId, t.message)
        return when {
            commitments.nothingAtStake() -> Pair(Aborted, listOf(ChannelAction.Message.Send(error)))
            else -> spendLocalCurrent().run { copy(second = second + ChannelAction.Message.Send(error)) }
        }
    }

    private fun ChannelContext.handleCommandResult(command: Command, result: Either<ChannelException, Pair<Commitments, LightningMessage>>, commit: Boolean): Pair<ChannelState, List<ChannelAction>> {
        return when (result) {
            is Either.Left -> handleCommandError(command, result.value, channelUpdate)
            is Either.Right -> {
                val (commitments1, message) = result.value
                val actions = mutableListOf<ChannelAction>(ChannelAction.Message.Send(message))
                if (commit) {
                    actions.add(ChannelAction.Message.SendToSelf(CMD_SIGN))
                }
                Pair(this@Normal.copy(commitments = commitments1), actions)
            }
        }
    }

    companion object {
        sealed class SpliceStatus {
            object None : SpliceStatus()
            data class Requested(val command: CMD_SPLICE, val spliceInit: SpliceInit) : SpliceStatus()
            data class InProgress(val spliceSession: InteractiveTxSession, val localPushAmount: MilliSatoshi, val remotePushAmount: MilliSatoshi, val origins: List<ChannelOrigin>) : SpliceStatus()
            data class WaitForCommitSig(val fundingParams: InteractiveTxParams, val fundingTx: SharedTransaction, val commitTxs: Helpers.Funding.FirstCommitTxs, val origins: List<ChannelOrigin>) : SpliceStatus()
            object Aborted : SpliceStatus()
        }
    }
}
