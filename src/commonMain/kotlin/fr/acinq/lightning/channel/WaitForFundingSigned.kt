package fr.acinq.lightning.channel

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.blockchain.BITCOIN_FUNDING_DEPTHOK
import fr.acinq.lightning.blockchain.WatchConfirmed
import fr.acinq.lightning.blockchain.electrum.WalletState
import fr.acinq.lightning.crypto.ShaChain
import fr.acinq.lightning.utils.Either
import fr.acinq.lightning.wire.*
import kotlin.math.absoluteValue

/*
 * We exchange signatures for a new channel.
 *
 *       Local                        Remote
 *         |         commit_sig         |
 *         |<---------------------------|
 *         |        tx_signatures       |
 *         |--------------------------->|
 */
data class WaitForFundingSigned(
    val localParams: LocalParams,
    val remoteParams: RemoteParams,
    val wallet: WalletState,
    val fundingParams: InteractiveTxParams,
    val localPushAmount: MilliSatoshi,
    val remotePushAmount: MilliSatoshi,
    val fundingTx: SharedTransaction,
    val firstCommitTxs: Helpers.Funding.FirstCommitTxs,
    val remoteFirstPerCommitmentPoint: PublicKey,
    val remoteSecondPerCommitmentPoint: PublicKey,
    val channelFlags: Byte,
    val channelConfig: ChannelConfig,
    val channelFeatures: ChannelFeatures,
    val channelOrigin: ChannelOrigin?
) : ChannelState() {
    val channelId: ByteVector32 = fundingParams.channelId

    override fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when {
            cmd is ChannelCommand.MessageReceived && cmd.message is CommitSig -> {
                val firstCommitmentRes = Helpers.Funding.receiveFirstCommitSig(
                    keyManager, fundingParams, localParams, remoteParams,
                    fundingTxIndex = 0, fundingTx,
                    commitmentIndex = 0, remoteFirstPerCommitmentPoint,
                    firstCommitTxs, remoteCommitSig = cmd.message,
                    currentBlockHeight.toLong()
                )
                when (firstCommitmentRes) {
                    Helpers.Funding.InvalidRemoteCommitSig -> handleLocalError(cmd, InvalidCommitmentSignature(channelId, firstCommitTxs.localCommitTx.tx.txid))
                    Helpers.Funding.FundingSigFailure -> {
                        logger.warning { "could not sign funding tx" }
                        Pair(Aborted, listOf(ChannelAction.Message.Send(Error(channelId, ChannelFundingError(channelId).message))))
                    }
                    is Helpers.Funding.FirstCommitment -> {
                        val (signedFundingTx, commitment) = firstCommitmentRes
                        val commitments = Commitments(
                            ChannelParams(channelId, channelConfig, channelFeatures, localParams, remoteParams, channelFlags),
                            CommitmentChanges.init(),
                            listOf(commitment),
                            payments = mapOf(),
                            remoteNextCommitInfo = Either.Right(remoteSecondPerCommitmentPoint),
                            remotePerCommitmentSecrets = ShaChain.init,
                            remoteChannelData = cmd.message.channelData
                        )
                        logger.info { "funding tx created with txId=${commitment.fundingTxId}. ${fundingTx.localInputs.size} local inputs, ${fundingTx.remoteInputs.size} remote inputs, ${fundingTx.localOutputs.size} local outputs and ${fundingTx.remoteOutputs.size} remote outputs" }
                        // We watch for confirmation in all cases, to allow pruning outdated commitments when transactions confirm.
                        val fundingMinDepth = Helpers.minDepthForFunding(staticParams.nodeParams, fundingParams.fundingAmount)
                        val watchConfirmed = WatchConfirmed(channelId, commitment.fundingTxId, commitment.commitInput.txOut.publicKeyScript, fundingMinDepth.toLong(), BITCOIN_FUNDING_DEPTHOK)
                        if (staticParams.useZeroConf) {
                            logger.info { "channel is using 0-conf, we won't wait for the funding tx to confirm" }
                            val nextPerCommitmentPoint = keyManager.commitmentPoint(localParams.channelKeys(keyManager).shaSeed, 1)
                            val channelReady = ChannelReady(channelId, nextPerCommitmentPoint, TlvStream(listOf(ChannelReadyTlv.ShortChannelIdTlv(ShortChannelId.peerId(staticParams.nodeParams.nodeId)))))
                            // We use part of the funding txid to create a dummy short channel id.
                            // This gives us a probability of collisions of 0.1% for 5 0-conf channels and 1% for 20
                            // Collisions mean that users may temporarily see incorrect numbers for their 0-conf channels (until they've been confirmed).
                            val shortChannelId = ShortChannelId(0, Pack.int32BE(commitment.fundingTxId.slice(0, 16).toByteArray()).absoluteValue, commitment.commitInput.outPoint.index.toInt())
                            val nextState = WaitForChannelReady(commitments, shortChannelId, channelReady)
                            val actions = buildList {
                                add(ChannelAction.Blockchain.SendWatch(watchConfirmed))
                                // We're not a liquidity provider, so we don't mind sending our signatures immediately.
                                add(ChannelAction.Message.Send(signedFundingTx.localSigs))
                                add(ChannelAction.Message.Send(channelReady))
                                add(ChannelAction.Storage.StoreState(nextState))
                            }
                            Pair(nextState, actions)
                        } else {
                            logger.info { "will wait for $fundingMinDepth confirmations" }
                            val nextState = WaitForFundingConfirmed(
                                commitments,
                                localPushAmount,
                                remotePushAmount,
                                currentBlockHeight.toLong(),
                                null
                            )
                            val actions = buildList {
                                add(ChannelAction.Blockchain.SendWatch(watchConfirmed))
                                add(ChannelAction.Storage.StoreState(nextState))
                                // We're not a liquidity provider, so we don't mind sending our signatures immediately.
                                add(ChannelAction.Message.Send(signedFundingTx.localSigs))
                            }
                            Pair(nextState, actions)
                        }
                    }
                }
            }
            cmd is ChannelCommand.MessageReceived && cmd.message is TxSignatures -> {
                logger.warning { "received tx_signatures before commit_sig, aborting" }
                handleLocalError(cmd, UnexpectedFundingSignatures(channelId))
            }
            cmd is ChannelCommand.MessageReceived && cmd.message is TxInitRbf -> {
                logger.info { "ignoring unexpected tx_init_rbf message" }
                Pair(this@WaitForFundingSigned, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidRbfAttempt(channelId).message))))
            }
            cmd is ChannelCommand.MessageReceived && cmd.message is TxAckRbf -> {
                logger.info { "ignoring unexpected tx_ack_rbf message" }
                Pair(this@WaitForFundingSigned, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidRbfAttempt(channelId).message))))
            }
            cmd is ChannelCommand.MessageReceived && cmd.message is TxAbort -> {
                logger.warning { "our peer aborted the dual funding flow: ascii='${cmd.message.toAscii()}' bin=${cmd.message.data.toHex()}" }
                Pair(Aborted, listOf(ChannelAction.Message.Send(TxAbort(channelId, DualFundingAborted(channelId, "requested by peer").message))))
            }
            cmd is ChannelCommand.MessageReceived && cmd.message is Error -> {
                logger.error { "peer sent error: ascii=${cmd.message.toAscii()} bin=${cmd.message.data.toHex()}" }
                Pair(Aborted, listOf())
            }
            cmd is ChannelCommand.ExecuteCommand && cmd.command is CloseCommand -> handleLocalError(cmd, ChannelFundingError(channelId))
            cmd is ChannelCommand.CheckHtlcTimeout -> Pair(this@WaitForFundingSigned, listOf())
            cmd is ChannelCommand.Disconnected -> Pair(Aborted, listOf())
            else -> unhandled(cmd)
        }
    }

    override fun ChannelContext.handleLocalError(cmd: ChannelCommand, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "error on command ${cmd::class.simpleName} in state ${this@WaitForFundingSigned::class.simpleName}" }
        val error = Error(channelId, t.message)
        return Pair(Aborted, listOf(ChannelAction.Message.Send(error)))
    }
}
