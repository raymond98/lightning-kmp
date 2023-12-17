package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.Lightning
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.electrum.WalletState
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.addHtlc
import fr.acinq.lightning.channel.TestsHelper.crossSign
import fr.acinq.lightning.channel.TestsHelper.fulfillHtlc
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.channel.TestsHelper.useAlternativeCommitSig
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.sum
import fr.acinq.lightning.utils.toMilliSatoshi
import fr.acinq.lightning.wire.*
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class SpliceTestsCommon : LightningTestSuite() {

    @Test
    fun `splice funds out`() {
        val (alice, bob) = reachNormal()
        spliceOut(alice, bob, 50_000.sat)
    }

    @Test
    fun `splice funds in`() {
        val (alice, bob) = reachNormal()
        spliceIn(alice, bob, listOf(50_000.sat))
    }

    @Test
    fun `splice funds in -- non-initiator`() {
        val (alice, bob) = reachNormal()
        spliceIn(bob, alice, listOf(50_000.sat))
    }

    @Test
    fun `splice funds in -- many utxos`() {
        val (alice, bob) = reachNormal()
        spliceIn(alice, bob, listOf(30_000.sat, 40_000.sat, 25_000.sat))
    }

    @Test
    fun `splice funds in -- local and remote commit index mismatch`() {
        // Alice and Bob asynchronously exchange HTLCs, which makes their commit indices diverge.
        val (nodes, preimages) = run {
            val (alice0, bob0) = reachNormal()
            // Alice sends an HTLC to Bob and signs it.
            val (nodes1, preimage1, _) = addHtlc(15_000_000.msat, alice0, bob0)
            val (alice1, bob1) = nodes1
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Commitment.Sign)
            val sigAlice1 = actionsAlice2.findOutgoingMessage<CommitSig>()
            // Bob sends an HTLC to Alice before receiving her commit_sig.
            val (nodes3, preimage2, _) = addHtlc(10_000_000.msat, bob1, alice2)
            val (bob3, alice3) = nodes3
            // Bob receives Alice's commit_sig and also signs his HTLC.
            val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(sigAlice1))
            val revBob1 = actionsBob4.findOutgoingMessage<RevokeAndAck>()
            actionsBob4.hasCommand<ChannelCommand.Commitment.Sign>()
            val (bob5, actionsBob5) = bob4.process(ChannelCommand.Commitment.Sign)
            val sigBob = actionsBob5.findOutgoingMessage<CommitSig>()
            val (alice4, _) = alice3.process(ChannelCommand.MessageReceived(revBob1))
            val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(sigBob))
            val revAlice = actionsAlice5.findOutgoingMessage<RevokeAndAck>()
            actionsAlice5.hasCommand<ChannelCommand.Commitment.Sign>()
            val (alice6, actionsAlice6) = alice5.process(ChannelCommand.Commitment.Sign)
            val sigAlice2 = actionsAlice6.findOutgoingMessage<CommitSig>()
            val (bob6, _) = bob5.process(ChannelCommand.MessageReceived(revAlice))
            val (bob7, actionsBob7) = bob6.process(ChannelCommand.MessageReceived(sigAlice2))
            assertIs<LNChannel<Normal>>(bob7)
            val revBob2 = actionsBob7.findOutgoingMessage<RevokeAndAck>()
            val (alice7, _) = alice6.process(ChannelCommand.MessageReceived(revBob2))
            assertIs<LNChannel<Normal>>(alice7)
            assertEquals(785_000_000.msat, alice7.commitments.latest.localCommit.spec.toLocal)
            assertEquals(190_000_000.msat, alice7.commitments.latest.localCommit.spec.toRemote)
            assertEquals(1, alice7.commitments.localCommitIndex)
            assertEquals(2, alice7.commitments.remoteCommitIndex)
            assertEquals(2, bob7.commitments.localCommitIndex)
            assertEquals(1, bob7.commitments.remoteCommitIndex)
            Pair(Pair(alice7, bob7), Pair(preimage1, preimage2))
        }

        // TODO: once we support quiescence, fulfill those HTLCs after the splice instead of before.
        val (alice1, bob1) = fulfillHtlc(0, preimages.first, nodes.first, nodes.second)
        val (bob2, alice2) = fulfillHtlc(0, preimages.second, bob1, alice1)
        val (alice3, bob3) = crossSign(alice2, bob2)
        assertEquals(2, alice3.commitments.localCommitIndex)
        assertEquals(4, alice3.commitments.remoteCommitIndex)

        spliceIn(alice3, bob3, listOf(500_000.sat))
    }

    @Test
    fun `splice cpfp`() {
        val (alice, bob) = reachNormal()
        spliceIn(alice, bob, listOf(50_000.sat))
        spliceOut(alice, bob, 50_000.sat)
        spliceCpfp(alice, bob)
    }

    @Test
    fun `splice to purchase inbound liquidity`() {
        val (alice, bob) = reachNormal()
        val leaseRate = LiquidityAds.LeaseRate(0, 250, 250 /* 2.5% */, 10.sat, 200, 100.msat)
        val liquidityRequest = LiquidityAds.RequestRemoteFunding(200_000.sat, alice.currentBlockHeight, leaseRate)
        val cmd = ChannelCommand.Commitment.Splice.Request(CompletableDeferred(), null, null, liquidityRequest, FeeratePerKw(1000.sat))
        val (alice1, actionsAlice1) = alice.process(cmd)
        val spliceInit = actionsAlice1.findOutgoingMessage<SpliceInit>()
        assertEquals(spliceInit.requestFunds, liquidityRequest.requestFunds)
        // Alice's contribution is negative: she needs to pay on-chain fees for the splice.
        assertTrue(spliceInit.fundingContribution < 0.sat)
        // We haven't implemented the seller side, so we mock it.
        val (_, actionsBob2) = bob.process(ChannelCommand.MessageReceived(spliceInit))
        val defaultSpliceAck = actionsBob2.findOutgoingMessage<SpliceAck>()
        assertNull(defaultSpliceAck.willFund)
        val fundingScript = Helpers.Funding.makeFundingPubKeyScript(spliceInit.fundingPubkey, defaultSpliceAck.fundingPubkey)
        run {
            val willFund = leaseRate.signLease(bob.staticParams.nodeParams.nodePrivateKey, fundingScript, spliceInit.requestFunds!!)
            val spliceAck = SpliceAck(alice.channelId, liquidityRequest.fundingAmount, 0.msat, defaultSpliceAck.fundingPubkey, willFund)
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(spliceAck))
            assertIs<Normal>(alice2.state)
            assertIs<SpliceStatus.InProgress>(alice2.state.spliceStatus)
            actionsAlice2.hasOutgoingMessage<TxAddInput>()
        }
        run {
            // Bob proposes different fees from what Alice expects.
            val bobLiquidityRates = leaseRate.copy(leaseFeeProportional = 500 /* 5% */)
            val willFund = bobLiquidityRates.signLease(bob.staticParams.nodeParams.nodePrivateKey, fundingScript, spliceInit.requestFunds!!)
            val spliceAck = SpliceAck(alice.channelId, liquidityRequest.fundingAmount, 0.msat, defaultSpliceAck.fundingPubkey, willFund)
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(spliceAck))
            assertIs<Normal>(alice2.state)
            assertIs<SpliceStatus.Aborted>(alice2.state.spliceStatus)
            actionsAlice2.hasOutgoingMessage<TxAbort>()
        }
        run {
            // Bob doesn't fund the splice.
            val spliceAck = SpliceAck(alice.channelId, liquidityRequest.fundingAmount, 0.msat, defaultSpliceAck.fundingPubkey, willFund = null)
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(spliceAck))
            assertIs<Normal>(alice2.state)
            assertIs<SpliceStatus.Aborted>(alice2.state.spliceStatus)
            actionsAlice2.hasOutgoingMessage<TxAbort>()
        }
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun `splice to purchase inbound liquidity -- not enough funds`() {
        val (_, bob) = reachNormal(aliceFundingAmount = 100_000.sat, bobFundingAmount = 10_000.sat, alicePushAmount = 0.msat, bobPushAmount = 0.msat)
        val leaseRate = LiquidityAds.LeaseRate(0, 0, 100 /* 5% */, 1.sat, 200, 100.msat)
        run {
            val liquidityRequest = LiquidityAds.RequestRemoteFunding(1_000_000.sat, bob.currentBlockHeight, leaseRate)
            assertEquals(10_001.sat, liquidityRequest.rate.fees(FeeratePerKw(1000.sat), liquidityRequest.fundingAmount, liquidityRequest.fundingAmount).total)
            val cmd = ChannelCommand.Commitment.Splice.Request(CompletableDeferred(), null, null, liquidityRequest, FeeratePerKw(1000.sat))
            val (_, actions1) = bob.process(cmd)
            assertTrue(actions1.isEmpty())
            assertTrue(cmd.replyTo.isCompleted)
            assertEquals(ChannelCommand.Commitment.Splice.Response.Failure.InsufficientFunds, cmd.replyTo.getCompleted())
        }
        run {
            val liquidityRequest = LiquidityAds.RequestRemoteFunding(1_000_000.sat, bob.currentBlockHeight, leaseRate.copy(leaseFeeBase = 0.sat))
            assertEquals(10_000.sat, liquidityRequest.rate.fees(FeeratePerKw(1000.sat), liquidityRequest.fundingAmount, liquidityRequest.fundingAmount).total)
            val cmd = ChannelCommand.Commitment.Splice.Request(CompletableDeferred(), null, null, liquidityRequest, FeeratePerKw(1000.sat))
            val (_, actions1) = bob.process(cmd)
            actions1.hasOutgoingMessage<SpliceInit>()
        }
    }

    @Test
    fun `reject splice_init`() {
        val cmd = createSpliceOutRequest(25_000.sat)
        val (alice, _) = reachNormal()
        val (alice1, actionsAlice1) = alice.process(cmd)
        actionsAlice1.hasOutgoingMessage<SpliceInit>()
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(TxAbort(alice.channelId, "thanks but no thanks")))
        assertIs<Normal>(alice2.state)
        assertEquals(alice2.state.spliceStatus, SpliceStatus.None)
        assertEquals(actionsAlice2.size, 1)
        actionsAlice2.hasOutgoingMessage<TxAbort>()
    }

    @Test
    fun `reject splice_ack`() {
        val cmd = createSpliceOutRequest(25_000.sat)
        val (alice, bob) = reachNormal()
        val (_, actionsAlice1) = alice.process(cmd)
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(actionsAlice1.hasOutgoingMessage<SpliceInit>()))
        actionsBob1.hasOutgoingMessage<SpliceAck>()
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(TxAbort(alice.channelId, "changed my mind")))
        assertIs<Normal>(bob2.state)
        assertEquals(bob2.state.spliceStatus, SpliceStatus.None)
        assertEquals(actionsBob2.size, 1)
        actionsBob2.hasOutgoingMessage<TxAbort>()
    }

    @Test
    fun `abort before tx_complete`() {
        val cmd = createSpliceOutRequest(20_000.sat)
        val (alice, bob) = reachNormal()
        val (alice1, actionsAlice1) = alice.process(cmd)
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<SpliceInit>()))
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(actionsBob1.findOutgoingMessage<SpliceAck>()))
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice2.findOutgoingMessage<TxAddInput>()))
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxComplete>()))
        actionsAlice3.hasOutgoingMessage<TxAddOutput>()
        run {
            val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(TxAbort(alice.channelId, "internal error")))
            assertIs<Normal>(alice4.state)
            assertEquals(alice4.state.spliceStatus, SpliceStatus.None)
            assertEquals(actionsAlice4.size, 1)
            actionsAlice4.hasOutgoingMessage<TxAbort>()
        }
        run {
            val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(TxAbort(alice.channelId, "internal error")))
            assertIs<Normal>(bob3.state)
            assertEquals(bob3.state.spliceStatus, SpliceStatus.None)
            assertEquals(actionsBob3.size, 1)
            actionsBob3.hasOutgoingMessage<TxAbort>()
        }
    }

    @Test
    fun `abort after tx_complete`() {
        val cmd = createSpliceOutRequest(31_000.sat)
        val (alice, bob) = reachNormal()
        val (alice1, actionsAlice1) = alice.process(cmd)
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<SpliceInit>()))
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(actionsBob1.findOutgoingMessage<SpliceAck>()))
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice2.findOutgoingMessage<TxAddInput>()))
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxComplete>()))
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(actionsAlice3.findOutgoingMessage<TxAddOutput>()))
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(actionsBob3.findOutgoingMessage<TxComplete>()))
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(actionsAlice4.findOutgoingMessage<TxAddOutput>()))
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(actionsBob4.findOutgoingMessage<TxComplete>()))
        actionsAlice5.hasOutgoingMessage<CommitSig>()
        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(actionsAlice5.findOutgoingMessage<TxComplete>()))
        actionsBob5.hasOutgoingMessage<CommitSig>()
        run {
            val (alice6, actionsAlice6) = alice5.process(ChannelCommand.MessageReceived(TxAbort(alice.channelId, "internal error")))
            assertIs<Normal>(alice6.state)
            assertEquals(alice6.state.spliceStatus, SpliceStatus.None)
            assertEquals(actionsAlice6.size, 2)
            actionsAlice6.hasOutgoingMessage<TxAbort>()
            actionsAlice6.has<ChannelAction.Storage.StoreState>()
        }
        run {
            val (bob6, actionsBob6) = bob5.process(ChannelCommand.MessageReceived(TxAbort(alice.channelId, "internal error")))
            assertIs<Normal>(bob6.state)
            assertEquals(bob6.state.spliceStatus, SpliceStatus.None)
            assertEquals(actionsBob6.size, 2)
            actionsBob6.hasOutgoingMessage<TxAbort>()
            actionsBob6.has<ChannelAction.Storage.StoreState>()
        }
    }

    @Test
    fun `abort after tx_complete then receive commit_sig`() {
        val cmd = createSpliceOutRequest(50_000.sat)
        val (alice, bob) = reachNormal()
        val (alice1, actionsAlice1) = alice.process(cmd)
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<SpliceInit>()))
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(actionsBob1.findOutgoingMessage<SpliceAck>()))
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice2.findOutgoingMessage<TxAddInput>()))
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxComplete>()))
        val txOut1 = actionsAlice3.findOutgoingMessage<TxAddOutput>()
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(txOut1))
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(actionsBob3.findOutgoingMessage<TxComplete>()))
        // Instead of relaying the second output, we duplicate the first one, which will make Bob abort after receiving tx_complete.
        actionsAlice4.hasOutgoingMessage<TxAddOutput>()
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(txOut1.copy(serialId = 100)))
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(actionsBob4.findOutgoingMessage<TxComplete>()))
        val commitSigAlice = actionsAlice5.findOutgoingMessage<CommitSig>()
        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(actionsAlice5.findOutgoingMessage<TxComplete>()))
        val txAbortBob = actionsBob5.findOutgoingMessage<TxAbort>()
        val (alice6, actionsAlice6) = alice5.process(ChannelCommand.MessageReceived(txAbortBob))
        assertIs<Normal>(alice6.state)
        assertEquals(1, alice6.commitments.active.size)
        assertEquals(SpliceStatus.None, alice6.state.spliceStatus)
        val txAbortAlice = actionsAlice6.findOutgoingMessage<TxAbort>()
        val (bob6, actionsBob6) = bob5.process(ChannelCommand.MessageReceived(commitSigAlice))
        assertTrue(actionsBob6.isEmpty())
        val (bob7, actionsBob7) = bob6.process(ChannelCommand.MessageReceived(txAbortAlice))
        assertIs<Normal>(bob7.state)
        assertEquals(1, bob7.commitments.active.size)
        assertEquals(SpliceStatus.None, bob7.state.spliceStatus)
        assertTrue(actionsBob7.isEmpty())
    }

    @Test
    fun `exchange splice_locked`() {
        val (alice, bob) = reachNormal()
        val (alice1, bob1) = spliceOut(alice, bob, 60_000.sat)
        val spliceTx = alice1.commitments.latest.localFundingStatus.signedTx!!

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_FUNDING_DEPTHOK, 100, 0, spliceTx)))
        assertEquals(alice2.commitments.active.size, 2)
        assertIs<LocalFundingStatus.ConfirmedFundingTx>(alice2.commitments.latest.localFundingStatus)
        assertEquals(actionsAlice2.size, 3)
        actionsAlice2.hasWatchFundingSpent(spliceTx.txid)
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        val spliceLockedAlice = actionsAlice2.hasOutgoingMessage<SpliceLocked>()

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(spliceLockedAlice))
        assertEquals(bob2.commitments.active.size, 2)
        assertEquals(actionsBob2.size, 1)
        actionsBob2.has<ChannelAction.Storage.StoreState>()
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 100, 0, spliceTx)))
        assertEquals(bob3.commitments.active.size, 1)
        assertIs<LocalFundingStatus.ConfirmedFundingTx>(bob3.commitments.latest.localFundingStatus)
        assertEquals(actionsBob3.size, 4)
        actionsBob3.hasWatchFundingSpent(spliceTx.txid)
        actionsBob3.has<ChannelAction.Storage.StoreState>()
        actionsBob3.has<ChannelAction.Storage.SetLocked>()
        val spliceLockedBob = actionsBob3.hasOutgoingMessage<SpliceLocked>()

        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(spliceLockedBob))
        assertEquals(alice3.commitments.active.size, 1)
        assertEquals(actionsAlice3.size, 2)
        actionsAlice3.has<ChannelAction.Storage.StoreState>()
        actionsAlice3.has<ChannelAction.Storage.SetLocked>()
    }

    @Test
    fun `exchange splice_locked -- zero-conf`() {
        val (alice, bob) = reachNormal(zeroConf = true)
        val (alice1, bob1) = spliceOut(alice, bob, 60_000.sat)
        val spliceTx = alice1.commitments.latest.localFundingStatus.signedTx!!

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(SpliceLocked(alice.channelId, spliceTx.txid)))
        assertEquals(actionsAlice2.size, 2)
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        actionsAlice2.has<ChannelAction.Storage.SetLocked>()
        assertEquals(alice2.commitments.active.size, 1)
        assertNotEquals(alice2.commitments.latest.fundingTxId, alice.commitments.latest.fundingTxId)
        assertIs<LocalFundingStatus.UnconfirmedFundingTx>(alice2.commitments.latest.localFundingStatus)

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(SpliceLocked(bob.channelId, spliceTx.txid)))
        assertEquals(actionsBob2.size, 2)
        actionsBob2.has<ChannelAction.Storage.StoreState>()
        actionsBob2.has<ChannelAction.Storage.SetLocked>()
        assertEquals(bob2.commitments.active.size, 1)
        assertNotEquals(bob2.commitments.latest.fundingTxId, bob.commitments.latest.fundingTxId)
        assertIs<LocalFundingStatus.UnconfirmedFundingTx>(bob2.commitments.latest.localFundingStatus)
    }

    @Test
    fun `remote splice_locked applies to previous splices`() {
        val (alice, bob) = reachNormal(zeroConf = true)
        val (alice1, bob1) = spliceOut(alice, bob, 60_000.sat)
        val spliceTx1 = alice1.commitments.latest.localFundingStatus.signedTx!!
        val (alice2, _) = spliceOut(alice1, bob1, 60_000.sat)
        val spliceTx2 = alice2.commitments.latest.localFundingStatus.signedTx!!

        val (_, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(SpliceLocked(alice.channelId, spliceTx2.txid)))
        assertEquals(3, actionsAlice3.size)
        actionsAlice3.has<ChannelAction.Storage.StoreState>()
        assertContains(actionsAlice3, ChannelAction.Storage.SetLocked(spliceTx1.txid))
        assertContains(actionsAlice3, ChannelAction.Storage.SetLocked(spliceTx2.txid))
    }

    @Test
    fun `use channel before splice_locked -- zero-conf`() {
        val (alice, bob) = reachNormal(zeroConf = true)
        val (alice1, bob1) = spliceOut(alice, bob, 50_000.sat)
        assertEquals(alice1.commitments.active.size, 2)
        assertEquals(bob1.commitments.active.size, 2)
        val spliceTx = alice1.commitments.latest.localFundingStatus.signedTx!!

        val (nodes2, preimage, htlc) = addHtlc(15_000_000.msat, alice1, bob1)
        val (alice3, bob3) = crossSign(nodes2.first, nodes2.second, commitmentsCount = 2)

        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(SpliceLocked(alice.channelId, spliceTx.txid)))
        actionsAlice4.has<ChannelAction.Storage.StoreState>()
        assertEquals(alice4.commitments.active.size, 1)
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(SpliceLocked(bob.channelId, spliceTx.txid)))
        actionsBob4.has<ChannelAction.Storage.StoreState>()
        assertEquals(bob4.commitments.active.size, 1)

        val (alice5, bob5) = fulfillHtlc(htlc.id, preimage, alice4, bob4)
        assertIs<LNChannel<Normal>>(alice5)
        assertIs<LNChannel<Normal>>(bob5)
        val (bob6, alice6) = crossSign(bob5, alice5, commitmentsCount = 1)
        listOf(bob6, alice6).forEach { node ->
            assertEquals(node.commitments.active.size, 1)
            assertEquals(node.commitments.inactive.size, 1)
            assertEquals(node.commitments.active.first().localCommit.index, node.commitments.inactive.first().localCommit.index + 1)
            assertEquals(node.commitments.active.first().remoteCommit.index, node.commitments.inactive.first().remoteCommit.index + 1)
            assertTrue(node.commitments.active.first().localCommit.spec.htlcs.isEmpty())
            assertTrue(node.commitments.inactive.first().localCommit.spec.htlcs.isNotEmpty())
        }
    }

    @Test
    fun `use channel during splice_locked -- zero-conf`() {
        val (alice, bob) = reachNormal(zeroConf = true)
        val (alice1, bob1) = spliceOut(alice, bob, 30_000.sat)
        val (alice2, bob2) = spliceOut(alice1, bob1, 20_000.sat)
        assertEquals(alice2.commitments.active.size, 3)
        assertEquals(bob2.commitments.active.size, 3)
        val spliceTx = alice2.commitments.latest.localFundingStatus.signedTx!!
        val spliceLocked = SpliceLocked(alice.channelId, spliceTx.txid)

        // Alice adds a new HTLC, and sends commit_sigs before receiving Bob's splice_locked.
        //
        //   Alice                           Bob
        //     |        splice_locked         |
        //     |----------------------------->|
        //     |       update_add_htlc        |
        //     |----------------------------->|
        //     |         commit_sig           | batch_size = 3
        //     |----------------------------->|
        //     |        splice_locked         |
        //     |<-----------------------------|
        //     |         commit_sig           | batch_size = 3
        //     |----------------------------->|
        //     |         commit_sig           | batch_size = 3
        //     |----------------------------->|
        //     |       revoke_and_ack         |
        //     |<-----------------------------|
        //     |         commit_sig           | batch_size = 1
        //     |<-----------------------------|
        //     |       revoke_and_ack         |
        //     |----------------------------->|

        val (bob3, _) = bob2.process(ChannelCommand.MessageReceived(spliceLocked))
        assertEquals(bob3.commitments.active.size, 1)
        assertEquals(bob3.commitments.inactive.size, 2)
        val (nodes, preimage, htlc) = addHtlc(20_000_000.msat, alice2, bob3)
        val (alice3, bob4) = nodes
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.Commitment.Sign)
        val commitSigsAlice = actionsAlice4.findOutgoingMessages<CommitSig>()
        assertEquals(commitSigsAlice.size, 3)
        commitSigsAlice.forEach { assertEquals(it.batchSize, 3) }
        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(commitSigsAlice[0]))
        assertTrue(actionsBob5.isEmpty())
        val (alice5, _) = alice4.process(ChannelCommand.MessageReceived(spliceLocked))
        assertEquals(alice5.commitments.active.size, 1)
        assertEquals(alice5.commitments.inactive.size, 2)
        val (bob6, actionsBob6) = bob5.process(ChannelCommand.MessageReceived(commitSigsAlice[1]))
        assertTrue(actionsBob6.isEmpty())
        val (bob7, actionsBob7) = bob6.process(ChannelCommand.MessageReceived(commitSigsAlice[2]))
        assertEquals(actionsBob7.size, 3)
        val revokeAndAckBob = actionsBob7.findOutgoingMessage<RevokeAndAck>()
        actionsBob7.contains(ChannelAction.Message.SendToSelf(ChannelCommand.Commitment.Sign))
        actionsBob7.has<ChannelAction.Storage.StoreState>()
        val (bob8, actionsBob8) = bob7.process(ChannelCommand.Commitment.Sign)
        assertEquals(actionsBob8.size, 3)
        val commitSigBob = actionsBob8.findOutgoingMessage<CommitSig>()
        assertEquals(commitSigBob.batchSize, 1)
        actionsBob8.has<ChannelAction.Storage.StoreHtlcInfos>()
        actionsBob8.has<ChannelAction.Storage.StoreState>()
        val (alice6, actionsAlice6) = alice5.process(ChannelCommand.MessageReceived(revokeAndAckBob))
        assertEquals(actionsAlice6.size, 1)
        actionsAlice6.has<ChannelAction.Storage.StoreState>()
        val (alice7, actionsAlice7) = alice6.process(ChannelCommand.MessageReceived(commitSigBob))
        assertIs<LNChannel<Normal>>(alice7)
        assertEquals(actionsAlice7.size, 2)
        val revokeAndAckAlice = actionsAlice7.findOutgoingMessage<RevokeAndAck>()
        actionsAlice7.has<ChannelAction.Storage.StoreState>()
        val (bob9, actionsBob9) = bob8.process(ChannelCommand.MessageReceived(revokeAndAckAlice))
        assertIs<LNChannel<Normal>>(bob9)
        assertEquals(actionsBob9.size, 2)
        actionsBob9.has<ChannelAction.ProcessIncomingHtlc>()
        actionsBob9.has<ChannelAction.Storage.StoreState>()

        // Bob fulfills the HTLC.
        val (alice8, bob10) = fulfillHtlc(htlc.id, preimage, alice7, bob9)
        val (bob11, alice9) = crossSign(bob10, alice8, commitmentsCount = 1)
        assertEquals(alice9.commitments.active.size, 1)
        alice9.commitments.inactive.forEach { assertTrue(it.localCommit.index < alice9.commitments.localCommitIndex) }
        assertEquals(bob11.commitments.active.size, 1)
        bob11.commitments.inactive.forEach { assertTrue(it.localCommit.index < bob11.commitments.localCommitIndex) }
    }

    @Test
    fun `disconnect -- commit_sig not received`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, _, bob1, _) = spliceOutWithoutSigs(alice, bob, 20_000.sat)
        val spliceStatus = alice1.state.spliceStatus
        assertIs<SpliceStatus.WaitingForSigs>(spliceStatus)

        val (alice2, bob2, channelReestablishAlice) = disconnect(alice1, bob1)
        assertEquals(channelReestablishAlice.nextFundingTxId, spliceStatus.session.fundingTx.txId)
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertIs<LNChannel<Normal>>(bob3)
        assertEquals(actionsBob3.size, 2)
        val channelReestablishBob = actionsBob3.findOutgoingMessage<ChannelReestablish>()
        val commitSigBob = actionsBob3.findOutgoingMessage<CommitSig>()
        assertEquals(channelReestablishBob.nextFundingTxId, spliceStatus.session.fundingTx.txId)
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertIs<LNChannel<Normal>>(alice3)
        assertEquals(actionsAlice3.size, 1)
        val commitSigAlice = actionsAlice3.findOutgoingMessage<CommitSig>()
        exchangeSpliceSigs(alice3, commitSigAlice, bob3, commitSigBob)
    }

    @Test
    fun `disconnect -- commit_sig received by alice`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, _, bob1, commitSigBob1) = spliceOutWithoutSigs(alice, bob, 20_000.sat)
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(commitSigBob1))
        assertIs<LNChannel<Normal>>(alice2)
        assertTrue(actionsAlice2.isEmpty())
        val spliceStatus = alice2.state.spliceStatus
        assertIs<SpliceStatus.WaitingForSigs>(spliceStatus)

        val (alice3, bob2, channelReestablishAlice) = disconnect(alice2, bob1)
        assertEquals(channelReestablishAlice.nextFundingTxId, spliceStatus.session.fundingTx.txId)
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertIs<LNChannel<Normal>>(bob3)
        assertEquals(actionsBob3.size, 2)
        val channelReestablishBob = actionsBob3.findOutgoingMessage<ChannelReestablish>()
        val commitSigBob2 = actionsBob3.findOutgoingMessage<CommitSig>()
        assertEquals(channelReestablishBob.nextFundingTxId, spliceStatus.session.fundingTx.txId)
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertIs<LNChannel<Normal>>(alice4)
        assertEquals(actionsAlice4.size, 1)
        val commitSigAlice = actionsAlice4.findOutgoingMessage<CommitSig>()
        exchangeSpliceSigs(alice4, commitSigAlice, bob3, commitSigBob2)
    }

    @Test
    fun `disconnect -- tx_signatures sent by bob`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, commitSigAlice1, bob1, _) = spliceOutWithoutSigs(alice, bob, 20_000.sat)
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(commitSigAlice1))
        assertIs<LNChannel<Normal>>(bob2)
        val spliceTxId = actionsBob2.hasOutgoingMessage<TxSignatures>().txId
        assertEquals(bob2.state.spliceStatus, SpliceStatus.None)

        val (alice2, bob3, channelReestablishAlice) = disconnect(alice1, bob2)
        assertEquals(channelReestablishAlice.nextFundingTxId, spliceTxId)
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(actionsBob4.size, 3)
        val channelReestablishBob = actionsBob4.findOutgoingMessage<ChannelReestablish>()
        val commitSigBob2 = actionsBob4.findOutgoingMessage<CommitSig>()
        val txSigsBob = actionsBob4.findOutgoingMessage<TxSignatures>()
        assertEquals(channelReestablishBob.nextFundingTxId, spliceTxId)
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertEquals(actionsAlice3.size, 1)
        val commitSigAlice2 = actionsAlice3.findOutgoingMessage<CommitSig>()

        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(commitSigBob2))
        assertTrue(actionsAlice4.isEmpty())
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<LNChannel<Normal>>(alice5)
        assertEquals(alice5.state.commitments.active.size, 2)
        assertEquals(actionsAlice5.size, 5)
        assertEquals(actionsAlice5.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.FundingTx).txid, spliceTxId)
        actionsAlice5.hasWatchConfirmed(spliceTxId)
        actionsAlice5.has<ChannelAction.Storage.StoreState>()
        actionsAlice5.has<ChannelAction.Storage.StoreOutgoingPayment.ViaSpliceOut>()
        val txSigsAlice = actionsAlice5.findOutgoingMessage<TxSignatures>()

        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(commitSigAlice2))
        assertTrue(actionsBob5.isEmpty())
        val (bob6, actionsBob6) = bob5.process(ChannelCommand.MessageReceived(txSigsAlice))
        assertIs<LNChannel<Normal>>(bob6)
        assertEquals(bob6.state.commitments.active.size, 2)
        assertEquals(actionsBob6.size, 2)
        assertEquals(actionsBob6.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.FundingTx).txid, spliceTxId)
        actionsBob6.has<ChannelAction.Storage.StoreState>()
    }

    @Test
    fun `disconnect -- tx_signatures sent by bob -- zero-conf`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx(zeroConf = true)
        val (alice1, commitSigAlice1, bob1, _) = spliceOutWithoutSigs(alice, bob, 20_000.sat)
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(commitSigAlice1))
        assertIs<LNChannel<Normal>>(bob2)
        val spliceTxId = actionsBob2.hasOutgoingMessage<TxSignatures>().txId
        actionsBob2.hasOutgoingMessage<SpliceLocked>()
        assertEquals(bob2.state.spliceStatus, SpliceStatus.None)

        val (alice2, bob3, channelReestablishAlice) = disconnect(alice1, bob2)
        assertEquals(channelReestablishAlice.nextFundingTxId, spliceTxId)
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(actionsBob4.size, 4)
        val channelReestablishBob = actionsBob4.findOutgoingMessage<ChannelReestablish>()
        val commitSigBob2 = actionsBob4.findOutgoingMessage<CommitSig>()
        val txSigsBob = actionsBob4.findOutgoingMessage<TxSignatures>()
        // splice_locked must always be sent *after* tx_signatures
        assertIs<SpliceLocked>(actionsBob4.filterIsInstance<ChannelAction.Message.Send>().last().message)
        val spliceLockedBob = actionsBob4.findOutgoingMessage<SpliceLocked>()
        assertEquals(channelReestablishBob.nextFundingTxId, spliceTxId)
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertEquals(actionsAlice3.size, 1)
        val commitSigAlice2 = actionsAlice3.findOutgoingMessage<CommitSig>()
        assertEquals(commitSigAlice1.signature, commitSigAlice2.signature)

        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(commitSigBob2))
        assertTrue(actionsAlice4.isEmpty())
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<LNChannel<Normal>>(alice5)
        assertEquals(alice5.state.commitments.active.size, 2)
        assertEquals(actionsAlice5.size, 6)
        assertEquals(actionsAlice5.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.FundingTx).txid, spliceTxId)
        actionsAlice5.hasWatchConfirmed(spliceTxId)
        actionsAlice5.has<ChannelAction.Storage.StoreState>()
        actionsAlice5.has<ChannelAction.Storage.StoreOutgoingPayment.ViaSpliceOut>()
        val txSigsAlice = actionsAlice5.findOutgoingMessage<TxSignatures>()
        assertIs<SpliceLocked>(actionsAlice5.filterIsInstance<ChannelAction.Message.Send>().last().message)
        val spliceLockedAlice = actionsAlice5.findOutgoingMessage<SpliceLocked>()
        val (alice6, actionsAlice6) = alice5.process(ChannelCommand.MessageReceived(spliceLockedBob))
        assertIs<LNChannel<Normal>>(alice6)
        assertEquals(alice6.state.commitments.active.size, 1)
        assertEquals(actionsAlice6.size, 2)
        actionsAlice6.find<ChannelAction.Storage.SetLocked>().also { assertEquals(it.txId, spliceTxId) }
        actionsAlice6.has<ChannelAction.Storage.StoreState>()

        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(commitSigAlice2))
        assertTrue(actionsBob5.isEmpty())
        val (bob6, actionsBob6) = bob5.process(ChannelCommand.MessageReceived(txSigsAlice))
        assertIs<LNChannel<Normal>>(bob6)
        assertEquals(bob6.state.commitments.active.size, 2)
        assertEquals(actionsBob6.size, 2)
        assertEquals(actionsBob6.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.FundingTx).txid, spliceTxId)
        actionsBob6.has<ChannelAction.Storage.StoreState>()
        val (bob7, actionsBob7) = bob6.process(ChannelCommand.MessageReceived(spliceLockedAlice))
        assertIs<LNChannel<Normal>>(bob7)
        assertEquals(bob7.state.commitments.active.size, 1)
        assertEquals(actionsBob7.size, 2)
        actionsBob7.find<ChannelAction.Storage.SetLocked>().also { assertEquals(it.txId, spliceTxId) }
        actionsBob7.has<ChannelAction.Storage.StoreState>()
    }

    @Test
    fun `disconnect -- tx_signatures sent by alice -- confirms while bob is offline`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, commitSigAlice1, bob1, commitSigBob1) = spliceOutWithoutSigs(alice, bob, 20_000.sat)

        // Bob completes the splice, but is missing Alice's tx_signatures.
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(commitSigAlice1))
        assertIs<LNChannel<Normal>>(bob2)
        val txSigsBob = actionsBob2.hasOutgoingMessage<TxSignatures>()
        assertEquals(bob2.state.spliceStatus, SpliceStatus.None)

        // Alice completes the splice, but Bob doesn't receive her tx_signatures.
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(commitSigBob1))
        assertTrue(actionsAlice2.isEmpty())
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<LNChannel<Normal>>(alice3)
        actionsAlice3.hasOutgoingMessage<TxSignatures>()
        assertEquals(alice3.state.spliceStatus, SpliceStatus.None)
        val spliceTx = alice3.commitments.latest.localFundingStatus.signedTx!!

        // The transaction confirms.
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_FUNDING_DEPTHOK, 100, 0, spliceTx)))
        assertIs<LNChannel<Normal>>(alice4)
        assertEquals(3, actionsAlice4.size)
        actionsAlice4.hasWatchFundingSpent(spliceTx.txid)
        actionsAlice4.hasOutgoingMessage<SpliceLocked>()
        actionsAlice4.has<ChannelAction.Storage.StoreState>()

        val (alice5, bob3, channelReestablishAlice) = disconnect(alice4, bob2)
        assertNull(channelReestablishAlice.nextFundingTxId)
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(1, actionsBob4.size)
        val channelReestablishBob = actionsBob4.findOutgoingMessage<ChannelReestablish>()
        assertEquals(channelReestablishBob.nextFundingTxId, spliceTx.txid)
        val (alice6, actionsAlice6) = alice5.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertIs<LNChannel<Normal>>(alice6)
        assertEquals(alice6.state.spliceStatus, SpliceStatus.None)
        assertEquals(2, actionsAlice6.size)
        val txSigsAlice = actionsAlice6.hasOutgoingMessage<TxSignatures>()
        actionsAlice6.hasOutgoingMessage<SpliceLocked>()

        // Bob receives tx_signatures, which completes the splice.
        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(txSigsAlice))
        assertIs<LNChannel<Normal>>(bob5)
        assertEquals(bob5.state.spliceStatus, SpliceStatus.None)
        assertEquals(2, actionsBob5.size)
        actionsBob5.hasPublishTx(spliceTx)
        actionsBob5.has<ChannelAction.Storage.StoreState>()
    }

    @Test
    fun `disconnect -- tx_signatures received by alice`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, commitSigAlice, bob1, commitSigBob) = spliceOutWithoutSigs(alice, bob, 20_000.sat)
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(commitSigBob))
        assertTrue(actionsAlice2.isEmpty())
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(commitSigAlice))
        assertIs<LNChannel<Normal>>(bob2)
        val txSigsBob = actionsBob2.findOutgoingMessage<TxSignatures>()
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<LNChannel<Normal>>(alice3)
        assertEquals(alice3.state.spliceStatus, SpliceStatus.None)
        actionsAlice3.hasOutgoingMessage<TxSignatures>()
        val spliceTx = actionsAlice3.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.FundingTx)

        val (alice4, bob3, channelReestablishAlice) = disconnect(alice3, bob2)
        assertNull(channelReestablishAlice.nextFundingTxId)
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(actionsBob4.size, 1)
        val channelReestablishBob = actionsBob4.findOutgoingMessage<ChannelReestablish>()
        assertEquals(channelReestablishBob.nextFundingTxId, spliceTx.txid)
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertIs<LNChannel<Normal>>(alice5)
        assertEquals(alice5.state.commitments.active.size, 2)
        assertEquals(actionsAlice5.size, 1)
        val txSigsAlice = actionsAlice5.findOutgoingMessage<TxSignatures>()

        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(txSigsAlice))
        assertIs<LNChannel<Normal>>(bob5)
        assertEquals(bob5.state.commitments.active.size, 2)
        assertEquals(actionsBob5.size, 2)
        assertEquals(actionsBob5.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.FundingTx).txid, spliceTx.txid)
        actionsBob5.has<ChannelAction.Storage.StoreState>()
    }

    @Test
    fun `disconnect -- splice_locked sent`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, bob1) = spliceOut(alice, bob, 70_000.sat)
        val spliceTx = alice1.commitments.latest.localFundingStatus.signedTx!!

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_FUNDING_DEPTHOK, 100, 0, spliceTx)))
        assertIs<LNChannel<Normal>>(alice2)
        val spliceLockedAlice1 = actionsAlice2.hasOutgoingMessage<SpliceLocked>()
        val (bob2, _) = bob1.process(ChannelCommand.MessageReceived(spliceLockedAlice1))
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 100, 0, spliceTx)))
        assertIs<LNChannel<Normal>>(bob3)
        actionsBob3.hasOutgoingMessage<SpliceLocked>()

        // Alice disconnects before receiving Bob's splice_locked.
        val (alice3, bob4, channelReestablishAlice) = disconnect(alice2, bob3)
        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(actionsBob5.size, 2)
        val channelReestablishBob = actionsBob5.findOutgoingMessage<ChannelReestablish>()
        val spliceLockedBob = actionsBob5.findOutgoingMessage<SpliceLocked>()

        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertEquals(actionsAlice4.size, 1)
        val spliceLockedAlice2 = actionsAlice4.hasOutgoingMessage<SpliceLocked>()
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(spliceLockedBob))
        assertIs<LNChannel<Normal>>(alice5)
        assertEquals(alice5.state.commitments.active.size, 1)
        assertEquals(2, actionsAlice5.size)
        actionsAlice5.has<ChannelAction.Storage.StoreState>()
        actionsAlice5.has<ChannelAction.Storage.SetLocked>()

        val (bob6, actionsBob6) = bob5.process(ChannelCommand.MessageReceived(spliceLockedAlice2))
        assertIs<LNChannel<Normal>>(bob6)
        assertEquals(bob6.state.commitments.active.size, 1)
        assertEquals(actionsBob6.size, 1)
        actionsBob6.has<ChannelAction.Storage.StoreState>()
    }

    @Test
    fun `disconnect -- latest commitment locked remotely and locally -- zero-conf`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx(zeroConf = true)
        val (alice1, bob1) = spliceOut(alice, bob, 40_000.sat)
        val (alice2, bob2) = spliceOut(alice1, bob1, 30_000.sat)

        // Alice and Bob have not received any remote splice_locked yet.
        assertEquals(alice2.commitments.active.size, 3)
        alice2.commitments.active.forEach { assertEquals(it.remoteFundingStatus, RemoteFundingStatus.NotLocked) }
        assertEquals(bob2.commitments.active.size, 3)
        bob2.commitments.active.forEach { assertEquals(it.remoteFundingStatus, RemoteFundingStatus.NotLocked) }

        // On reconnection, Alice and Bob only send splice_locked for the latest commitment.
        val (alice3, bob3, channelReestablishAlice) = disconnect(alice2, bob2)
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(actionsBob4.size, 2)
        val channelReestablishBob = actionsBob4.findOutgoingMessage<ChannelReestablish>()
        val spliceLockedBob = actionsBob4.findOutgoingMessage<SpliceLocked>()
        assertEquals(spliceLockedBob.fundingTxId, bob2.commitments.latest.fundingTxId)

        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertEquals(actionsAlice4.size, 1)
        val spliceLockedAlice = actionsAlice4.hasOutgoingMessage<SpliceLocked>()
        assertEquals(spliceLockedAlice.fundingTxId, spliceLockedBob.fundingTxId)
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(spliceLockedBob))
        assertEquals(actionsAlice5.size, 3)
        assertEquals(alice5.commitments.active.size, 1)
        assertEquals(alice5.commitments.latest.fundingTxId, spliceLockedBob.fundingTxId)
        actionsAlice5.has<ChannelAction.Storage.StoreState>()
        assertContains(actionsAlice5, ChannelAction.Storage.SetLocked(alice1.commitments.latest.fundingTxId))
        assertContains(actionsAlice5, ChannelAction.Storage.SetLocked(alice2.commitments.latest.fundingTxId))

        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(spliceLockedAlice))
        assertEquals(actionsBob5.size, 3)
        assertEquals(bob5.commitments.active.size, 1)
        assertEquals(bob5.commitments.latest.fundingTxId, spliceLockedAlice.fundingTxId)
        actionsBob5.has<ChannelAction.Storage.StoreState>()
        assertContains(actionsBob5, ChannelAction.Storage.SetLocked(bob1.commitments.latest.fundingTxId))
        assertContains(actionsBob5, ChannelAction.Storage.SetLocked(bob2.commitments.latest.fundingTxId))
    }

    @Test
    fun `disconnect -- latest commitment locked remotely but not locally`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, bob1) = spliceOut(alice, bob, 40_000.sat)
        val spliceTx1 = alice1.commitments.latest.localFundingStatus.signedTx!!
        val (alice2, bob2) = spliceOut(alice1, bob1, 30_000.sat)
        val spliceTx2 = alice2.commitments.latest.localFundingStatus.signedTx!!
        assertNotEquals(spliceTx1.txid, spliceTx2.txid)

        // Alice and Bob have not received any remote splice_locked yet.
        assertEquals(alice2.commitments.active.size, 3)
        alice2.commitments.active.forEach { assertEquals(it.remoteFundingStatus, RemoteFundingStatus.NotLocked) }
        assertEquals(bob2.commitments.active.size, 3)
        bob2.commitments.active.forEach { assertEquals(it.remoteFundingStatus, RemoteFundingStatus.NotLocked) }

        // Alice locks the last commitment.
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_FUNDING_DEPTHOK, 100, 0, spliceTx2)))
        assertIs<LNChannel<Normal>>(alice3)
        assertEquals(actionsAlice3.size, 3)
        assertEquals(actionsAlice3.hasOutgoingMessage<SpliceLocked>().fundingTxId, spliceTx2.txid)
        actionsAlice3.hasWatchFundingSpent(spliceTx2.txid)
        actionsAlice3.has<ChannelAction.Storage.StoreState>()

        // Bob locks the previous commitment.
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 100, 0, spliceTx1)))
        assertIs<LNChannel<Normal>>(bob3)
        assertEquals(actionsBob3.size, 3)
        assertEquals(actionsBob3.hasOutgoingMessage<SpliceLocked>().fundingTxId, spliceTx1.txid)
        actionsBob3.hasWatchFundingSpent(spliceTx1.txid)
        actionsBob3.has<ChannelAction.Storage.StoreState>()

        // Alice and Bob disconnect before receiving each other's splice_locked.
        // On reconnection, the latest commitment is still unlocked by Bob so they have two active commitments.
        val (alice4, bob4, channelReestablishAlice) = disconnect(alice3, bob3)
        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(actionsBob5.size, 2)
        val channelReestablishBob = actionsBob5.findOutgoingMessage<ChannelReestablish>()
        val spliceLockedBob = actionsBob5.findOutgoingMessage<SpliceLocked>()
        assertEquals(spliceLockedBob.fundingTxId, spliceTx1.txid)

        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertEquals(actionsAlice5.size, 1)
        val spliceLockedAlice = actionsAlice5.hasOutgoingMessage<SpliceLocked>()
        assertEquals(spliceLockedAlice.fundingTxId, spliceTx2.txid)
        val (alice6, actionsAlice6) = alice5.process(ChannelCommand.MessageReceived(spliceLockedBob))
        assertEquals(actionsAlice6.size, 2)
        assertEquals(alice6.commitments.active.map { it.fundingTxId }, listOf(spliceTx2.txid, spliceTx1.txid))
        actionsAlice6.has<ChannelAction.Storage.StoreState>()
        actionsAlice6.contains(ChannelAction.Storage.SetLocked(spliceTx1.txid))

        val (bob6, actionsBob6) = bob5.process(ChannelCommand.MessageReceived(spliceLockedAlice))
        assertEquals(actionsBob6.size, 2)
        assertEquals(bob6.commitments.active.map { it.fundingTxId }, listOf(spliceTx2.txid, spliceTx1.txid))
        actionsBob6.has<ChannelAction.Storage.StoreState>()
        actionsBob6.contains(ChannelAction.Storage.SetLocked(spliceTx1.txid))
    }

    @Test
    fun `disconnect -- splice tx published`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, bob1) = spliceOut(alice, bob, 40_000.sat)
        val spliceTx = alice1.commitments.latest.localFundingStatus.signedTx!!

        val (alice2, _) = alice1.process(ChannelCommand.Disconnected)
        val (bob2, _) = bob1.process(ChannelCommand.Disconnected)
        assertIs<Offline>(alice2.state)
        assertIs<Offline>(bob2.state)

        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, spliceTx)))
        assertIs<Offline>(alice3.state)
        assertTrue(actionsAlice3.isEmpty())
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.WatchReceived(WatchEventSpent(bob.channelId, BITCOIN_FUNDING_SPENT, spliceTx)))
        assertIs<Offline>(bob3.state)
        assertTrue(actionsBob3.isEmpty())
    }

    @Test
    fun `force-close -- latest active commitment`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, bob1) = spliceOut(alice, bob, 75_000.sat)

        // Bob force-closes using the latest active commitment.
        val bobCommitTx = bob1.commitments.active.first().localCommit.publishableTxs.commitTx.tx
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.Close.ForceClose)
        assertIs<Closing>(bob2.state)
        assertEquals(actionsBob2.size, 7)
        assertEquals(actionsBob2.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.CommitTx).txid, bobCommitTx.txid)
        val claimMain = actionsBob2.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.ClaimLocalDelayedOutputTx)
        actionsBob2.hasWatchConfirmed(bobCommitTx.txid)
        actionsBob2.hasWatchConfirmed(claimMain.txid)
        actionsBob2.has<ChannelAction.Storage.StoreState>()
        actionsBob2.hasOutgoingMessage<Error>()
        actionsBob2.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()

        // Alice detects the force-close.
        val commitment = alice1.commitments.active.first()
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
        assertIs<LNChannel<Closing>>(alice2)
        actionsAlice2.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()
        handleRemoteClose(alice2, actionsAlice2, commitment, bobCommitTx)
    }

    @Test
    fun `force-close -- latest active commitment -- alternative feerate`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, commitSigAlice, bob1, commitSigBob) = spliceOutWithoutSigs(alice, bob, 75_000.sat)
        val (alice2, bob2) = exchangeSpliceSigs(alice1, commitSigAlice, bob1, commitSigBob)

        // Bob force-closes using the latest active commitment and an optional feerate.
        val bobCommitTx = useAlternativeCommitSig(bob2, bob2.commitments.active.first(), commitSigAlice.alternativeFeerateSigs.last())
        val commitment = alice1.commitments.active.first()
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
        assertIs<LNChannel<Closing>>(alice3)
        actionsAlice3.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()
        handleRemoteClose(alice3, actionsAlice3, commitment, bobCommitTx)
    }

    @Test
    fun `force-close -- previous active commitment`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, bob1) = spliceOut(alice, bob, 75_000.sat)

        // Bob force-closes using an older active commitment.
        assertEquals(bob1.commitments.active.map { it.localCommit.publishableTxs.commitTx.tx }.toSet().size, 2)
        val bobCommitTx = bob1.commitments.active.last().localCommit.publishableTxs.commitTx.tx
        handlePreviousRemoteClose(alice1, bobCommitTx)
    }

    @Test
    fun `force-close -- previous active commitment -- alternative feerate`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, commitSigAlice1, bob1, commitSigBob1) = spliceOutWithoutSigs(alice, bob, 75_000.sat)
        val (alice2, bob2) = exchangeSpliceSigs(alice1, commitSigAlice1, bob1, commitSigBob1)
        val (alice3, commitSigAlice3, bob3, commitSigBob3) = spliceOutWithoutSigs(alice2, bob2, 75_000.sat)
        val (alice4, bob4) = exchangeSpliceSigs(alice3, commitSigAlice3, bob3, commitSigBob3)

        // Bob force-closes using an older active commitment with an alternative feerate.
        assertEquals(bob4.commitments.active.map { it.localCommit.publishableTxs.commitTx.tx }.toSet().size, 3)
        val bobCommitTx = useAlternativeCommitSig(bob4, bob4.commitments.active[1], commitSigAlice1.alternativeFeerateSigs.first())
        handlePreviousRemoteClose(alice4, bobCommitTx)
    }

    @Test
    fun `force-close -- previous inactive commitment`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx(zeroConf = true)
        val (alice1, bob1) = spliceOut(alice, bob, 50_000.sat)
        val spliceTx = alice1.commitments.latest.localFundingStatus.signedTx!!
        val (alice2, _) = alice1.process(ChannelCommand.MessageReceived(SpliceLocked(alice.channelId, spliceTx.txid)))
        assertEquals(alice2.commitments.active.size, 1)
        assertEquals(alice2.commitments.inactive.size, 1)
        val (bob2, _) = bob1.process(ChannelCommand.MessageReceived(SpliceLocked(bob.channelId, spliceTx.txid)))
        assertEquals(bob2.commitments.active.size, 1)
        assertEquals(bob2.commitments.inactive.size, 1)

        // Bob force-closes using an inactive commitment.
        assertNotEquals(bob2.commitments.active.first().fundingTxId, bob2.commitments.inactive.first().fundingTxId)
        val bobCommitTx = bob2.commitments.inactive.first().localCommit.publishableTxs.commitTx.tx
        handlePreviousRemoteClose(alice1, bobCommitTx)
    }

    @Test
    fun `force-close -- revoked latest active commitment`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, bob1) = spliceOut(alice, bob, 50_000.sat)
        val bobCommitTx = bob1.commitments.active.first().localCommit.publishableTxs.commitTx.tx

        // Alice sends an HTLC to Bob, which revokes the previous commitment.
        val (nodes2, _, _) = addHtlc(25_000_000.msat, alice1, bob1)
        val (alice3, bob3) = crossSign(nodes2.first, nodes2.second, commitmentsCount = 2)
        assertEquals(alice3.commitments.active.size, 2)
        assertEquals(bob3.commitments.active.size, 2)

        // Bob force-closes using the revoked commitment.
        handleCurrentRevokedRemoteClose(alice3, bobCommitTx)
    }

    @Test
    fun `force-close -- revoked latest active commitment -- alternative feerate`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, commitSigAlice, bob1, commitSigBob) = spliceOutWithoutSigs(alice, bob, 50_000.sat)
        val (alice2, bob2) = exchangeSpliceSigs(alice1, commitSigAlice, bob1, commitSigBob)
        val bobCommitTx = useAlternativeCommitSig(bob2, bob2.commitments.active.first(), commitSigAlice.alternativeFeerateSigs.first())

        // Alice sends an HTLC to Bob, which revokes the previous commitment.
        val (nodes3, _, _) = addHtlc(25_000_000.msat, alice2, bob2)
        val (alice4, bob4) = crossSign(nodes3.first, nodes3.second, commitmentsCount = 2)
        assertEquals(alice4.commitments.active.size, 2)
        assertEquals(bob4.commitments.active.size, 2)

        // Bob force-closes using the revoked commitment.
        handleCurrentRevokedRemoteClose(alice4, bobCommitTx)
    }

    @Test
    fun `force-close -- revoked previous active commitment`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx()
        val (alice1, bob1) = spliceOut(alice, bob, 50_000.sat)
        val bobCommitTx = bob1.commitments.active.last().localCommit.publishableTxs.commitTx.tx

        // Alice sends an HTLC to Bob, which revokes the previous commitment.
        val (nodes2, preimage, htlc) = addHtlc(25_000_000.msat, alice1, bob1)
        val (alice3, bob3) = crossSign(nodes2.first, nodes2.second, commitmentsCount = 2)
        val (alice4, bob4) = fulfillHtlc(htlc.id, preimage, alice3, bob3)
        val (bob5, alice5) = crossSign(bob4, alice4, commitmentsCount = 2)
        assertEquals(alice5.commitments.active.size, 2)
        assertEquals(bob5.commitments.active.size, 2)

        // Bob force-closes using the revoked commitment.
        handlePreviousRevokedRemoteClose(alice5, bobCommitTx)
    }

    @Test
    fun `force-close -- revoked previous inactive commitment`() {
        val (alice, bob) = reachNormalWithConfirmedFundingTx(zeroConf = true)
        val (alice1, bob1) = spliceOut(alice, bob, 50_000.sat)
        val spliceTx = alice1.commitments.latest.localFundingStatus.signedTx!!
        val (alice2, _) = alice1.process(ChannelCommand.MessageReceived(SpliceLocked(alice.channelId, spliceTx.txid)))
        assertIs<LNChannel<Normal>>(alice2)
        assertEquals(alice2.commitments.active.size, 1)
        assertEquals(alice2.commitments.inactive.size, 1)
        val (bob2, _) = bob1.process(ChannelCommand.MessageReceived(SpliceLocked(bob.channelId, spliceTx.txid)))
        assertIs<LNChannel<Normal>>(bob2)
        assertEquals(bob2.commitments.active.size, 1)
        assertEquals(bob2.commitments.inactive.size, 1)
        val bobCommitTx = bob2.commitments.inactive.first().localCommit.publishableTxs.commitTx.tx

        // Alice sends an HTLC to Bob, which revokes the inactive commitment.
        val (nodes3, preimage, htlc) = addHtlc(25_000_000.msat, alice2, bob2)
        val (alice4, bob4) = crossSign(nodes3.first, nodes3.second, commitmentsCount = 1)
        val (alice5, bob5) = fulfillHtlc(htlc.id, preimage, alice4, bob4)
        val (_, alice6) = crossSign(bob5, alice5, commitmentsCount = 1)

        // Bob force-closes using the revoked commitment.
        handlePreviousRevokedRemoteClose(alice6, bobCommitTx)
    }

    companion object {
        private fun reachNormalWithConfirmedFundingTx(zeroConf: Boolean = false): Pair<LNChannel<Normal>, LNChannel<Normal>> {
            val (alice, bob) = reachNormal(zeroConf = zeroConf)
            val fundingTx = alice.commitments.latest.localFundingStatus.signedTx!!
            val (alice1, _) = alice.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 3, fundingTx)))
            val (bob1, _) = bob.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 3, fundingTx)))
            val (nodes2, preimage, htlc) = addHtlc(5_000.msat, alice1, bob1)
            val (alice2, bob2) = nodes2
            assertIs<LNChannel<Normal>>(alice2)
            assertIs<LNChannel<Normal>>(bob2)
            val (alice3, bob3) = crossSign(alice2, bob2, commitmentsCount = 1)
            val (alice4, bob4) = fulfillHtlc(htlc.id, preimage, alice3, bob3)
            val (bob5, alice5) = crossSign(bob4, alice4, commitmentsCount = 1)
            return Pair(alice5, bob5)
        }

        private fun createSpliceOutRequest(amount: Satoshi): ChannelCommand.Commitment.Splice.Request = ChannelCommand.Commitment.Splice.Request(
            replyTo = CompletableDeferred(),
            spliceIn = null,
            spliceOut = ChannelCommand.Commitment.Splice.Request.SpliceOut(amount, Script.write(Script.pay2wpkh(randomKey().publicKey())).byteVector()),
            requestRemoteFunding = null,
            feerate = FeeratePerKw(253.sat)
        )

        private fun spliceOut(alice: LNChannel<Normal>, bob: LNChannel<Normal>, amount: Satoshi): Pair<LNChannel<Normal>, LNChannel<Normal>> {
            val (alice1, commitSigAlice, bob1, commitSigBob) = spliceOutWithoutSigs(alice, bob, amount)
            return exchangeSpliceSigs(alice1, commitSigAlice, bob1, commitSigBob)
        }

        data class UnsignedSpliceFixture(val alice: LNChannel<Normal>, val commitSigAlice: CommitSig, val bob: LNChannel<Normal>, val commitSigBob: CommitSig)

        private fun spliceOutWithoutSigs(alice: LNChannel<Normal>, bob: LNChannel<Normal>, amount: Satoshi): UnsignedSpliceFixture {
            val parentCommitment = alice.commitments.active.first()
            val cmd = createSpliceOutRequest(amount)
            // Negotiate a splice transaction where Alice is the only contributor.
            val (alice1, actionsAlice1) = alice.process(cmd)
            val spliceInit = actionsAlice1.findOutgoingMessage<SpliceInit>()
            // Alice takes more than the spliced out amount from her local balance because she must pay on-chain fees.
            assertTrue(-amount - 500.sat < spliceInit.fundingContribution && spliceInit.fundingContribution < -amount)
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(spliceInit))
            val spliceAck = actionsBob1.findOutgoingMessage<SpliceAck>()
            assertEquals(spliceAck.fundingContribution, 0.sat)
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(spliceAck))
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice2.findOutgoingMessage<TxAddInput>()))
            val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxComplete>()))
            val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(actionsAlice3.findOutgoingMessage<TxAddOutput>()))
            val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(actionsBob3.findOutgoingMessage<TxComplete>()))
            val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(actionsAlice4.findOutgoingMessage<TxAddOutput>()))
            val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(actionsBob4.findOutgoingMessage<TxComplete>()))
            assertIs<LNChannel<Normal>>(alice5)
            val commitSigAlice = actionsAlice5.findOutgoingMessage<CommitSig>()
            actionsAlice5.has<ChannelAction.Storage.StoreState>()
            val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(actionsAlice5.findOutgoingMessage<TxComplete>()))
            assertIs<LNChannel<Normal>>(bob5)
            val commitSigBob = actionsBob5.findOutgoingMessage<CommitSig>()
            actionsBob5.has<ChannelAction.Storage.StoreState>()
            checkCommandResponse(cmd.replyTo, parentCommitment, spliceInit)
            return UnsignedSpliceFixture(alice5, commitSigAlice, bob5, commitSigBob)
        }

        fun spliceIn(alice: LNChannel<Normal>, bob: LNChannel<Normal>, amounts: List<Satoshi>): Pair<LNChannel<Normal>, LNChannel<Normal>> {
            val parentCommitment = alice.commitments.active.first()
            val cmd = ChannelCommand.Commitment.Splice.Request(
                replyTo = CompletableDeferred(),
                spliceIn = ChannelCommand.Commitment.Splice.Request.SpliceIn(createWalletWithFunds(alice.staticParams.nodeParams.keyManager, amounts)),
                spliceOut = null,
                requestRemoteFunding = null,
                feerate = FeeratePerKw(253.sat)
            )

            // Negotiate a splice transaction where Alice is the only contributor.
            val (alice1, actionsAlice1) = alice.process(cmd)
            val spliceInit = actionsAlice1.findOutgoingMessage<SpliceInit>()
            // Alice adds slightly less than her wallet amount because she must pay on-chain fees.
            assertTrue(amounts.sum() - 500.sat < spliceInit.fundingContribution && spliceInit.fundingContribution < amounts.sum())
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(spliceInit))
            val spliceAck = actionsBob1.findOutgoingMessage<SpliceAck>()
            assertEquals(spliceAck.fundingContribution, 0.sat)
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(spliceAck))
            // Alice adds the shared input and one input per wallet utxo.
            val (alice3, actionsAlice3, bob2) = (0 until amounts.size + 1).fold(Triple(alice2, actionsAlice2, bob1)) { triple, _ ->
                val (alicePrev, actionsAlicePrev, bobPrev) = triple
                val (bobNext, actionsBobNext) = bobPrev.process(ChannelCommand.MessageReceived(actionsAlicePrev.findOutgoingMessage<TxAddInput>()))
                val (aliceNext, actionsAliceNext) = alicePrev.process(ChannelCommand.MessageReceived(actionsBobNext.findOutgoingMessage<TxComplete>()))
                Triple(aliceNext, actionsAliceNext, bobNext)
            }
            val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(actionsAlice3.findOutgoingMessage<TxAddOutput>()))
            val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(actionsBob3.findOutgoingMessage<TxComplete>()))
            assertIs<LNChannel<Normal>>(alice4)
            val commitSigAlice = actionsAlice4.findOutgoingMessage<CommitSig>()
            actionsAlice4.has<ChannelAction.Storage.StoreState>()
            val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(actionsAlice4.findOutgoingMessage<TxComplete>()))
            assertIs<LNChannel<Normal>>(bob4)
            val commitSigBob = actionsBob4.findOutgoingMessage<CommitSig>()
            actionsBob4.has<ChannelAction.Storage.StoreState>()

            checkCommandResponse(cmd.replyTo, parentCommitment, spliceInit)
            return exchangeSpliceSigs(alice4, commitSigAlice, bob4, commitSigBob)
        }

        private fun spliceCpfp(alice: LNChannel<Normal>, bob: LNChannel<Normal>): Pair<LNChannel<Normal>, LNChannel<Normal>> {
            val parentCommitment = alice.commitments.active.first()
            val cmd = ChannelCommand.Commitment.Splice.Request(
                replyTo = CompletableDeferred(),
                spliceIn = null,
                spliceOut = null,
                requestRemoteFunding = null,
                feerate = FeeratePerKw(253.sat)
            )

            // Negotiate a splice transaction with no contribution.
            val (alice1, actionsAlice1) = alice.process(cmd)
            val spliceInit = actionsAlice1.findOutgoingMessage<SpliceInit>()
            // Alice's contribution is negative: that amount goes to on-chain fees.
            assertTrue(spliceInit.fundingContribution < 0.sat)
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(spliceInit))
            val spliceAck = actionsBob1.findOutgoingMessage<SpliceAck>()
            assertEquals(spliceAck.fundingContribution, 0.sat)
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(spliceAck))
            // Alice adds one shared input and one shared output
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice2.findOutgoingMessage<TxAddInput>()))
            val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxComplete>()))
            val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(actionsAlice3.findOutgoingMessage<TxAddOutput>()))
            val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(actionsBob3.findOutgoingMessage<TxComplete>()))
            assertIs<LNChannel<Normal>>(alice4)
            val commitSigAlice = actionsAlice4.findOutgoingMessage<CommitSig>()
            actionsAlice4.has<ChannelAction.Storage.StoreState>()
            val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(actionsAlice4.findOutgoingMessage<TxComplete>()))
            assertIs<LNChannel<Normal>>(bob4)
            val commitSigBob = actionsBob4.findOutgoingMessage<CommitSig>()
            actionsBob4.has<ChannelAction.Storage.StoreState>()

            checkCommandResponse(cmd.replyTo, parentCommitment, spliceInit)
            return exchangeSpliceSigs(alice4, commitSigAlice, bob4, commitSigBob)
        }

        private fun checkCommandResponse(replyTo: CompletableDeferred<ChannelCommand.Commitment.Splice.Response>, parentCommitment: Commitment, spliceInit: SpliceInit): TxId = runBlocking {
            val response = replyTo.await()
            assertIs<ChannelCommand.Commitment.Splice.Response.Created>(response)
            assertEquals(response.capacity, parentCommitment.fundingAmount + spliceInit.fundingContribution)
            assertEquals(response.balance, parentCommitment.localCommit.spec.toLocal + spliceInit.fundingContribution.toMilliSatoshi())
            assertEquals(response.fundingTxIndex, parentCommitment.fundingTxIndex + 1)
            response.fundingTxId
        }

        private fun exchangeSpliceSigs(alice: LNChannel<Normal>, commitSigAlice: CommitSig, bob: LNChannel<Normal>, commitSigBob: CommitSig): Pair<LNChannel<Normal>, LNChannel<Normal>> {
            val aliceSpliceStatus = alice.state.spliceStatus
            assertIs<SpliceStatus.WaitingForSigs>(aliceSpliceStatus)
            val bobSpliceStatus = bob.state.spliceStatus
            assertIs<SpliceStatus.WaitingForSigs>(bobSpliceStatus)

            val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(commitSigBob))
            assertTrue(actionsAlice1.isEmpty())
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(commitSigAlice))
            when {
                bob1.staticParams.useZeroConf -> assertEquals(actionsBob1.size, 4)
                else -> assertEquals(actionsBob1.size, 3)
            }
            val txSigsBob = actionsBob1.findOutgoingMessage<TxSignatures>()
            assertEquals(txSigsBob.swapInServerSigs.size, aliceSpliceStatus.session.fundingTx.tx.localInputs.size)
            actionsBob1.hasWatchConfirmed(txSigsBob.txId)
            actionsBob1.has<ChannelAction.Storage.StoreState>()
            if (bob1.staticParams.useZeroConf) {
                assertEquals(actionsBob1.hasOutgoingMessage<SpliceLocked>().fundingTxId, txSigsBob.txId)
            }
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(txSigsBob))
            if (alice1.staticParams.useZeroConf) {
                actionsAlice2.hasOutgoingMessage<SpliceLocked>()
            } else {
                assertTrue { actionsAlice2.filterIsInstance<ChannelAction.Message.Send>().none { it.message is SpliceLocked } }
            }
            val txSigsAlice = actionsAlice2.findOutgoingMessage<TxSignatures>()
            assertEquals(txSigsAlice.swapInServerSigs.size, bobSpliceStatus.session.fundingTx.tx.localInputs.size)
            assertEquals(actionsAlice2.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.FundingTx).txid, txSigsAlice.txId)
            actionsAlice2.hasWatchConfirmed(txSigsAlice.txId)
            actionsAlice2.has<ChannelAction.Storage.StoreState>()
            when {
                aliceSpliceStatus.session.fundingParams.localContribution > 0.sat -> actionsAlice2.has<ChannelAction.Storage.StoreIncomingPayment.ViaSpliceIn>()
                aliceSpliceStatus.session.fundingParams.localContribution < 0.sat && aliceSpliceStatus.session.fundingParams.localOutputs.isNotEmpty() -> actionsAlice2.has<ChannelAction.Storage.StoreOutgoingPayment.ViaSpliceOut>()
                aliceSpliceStatus.session.fundingParams.localContribution < 0.sat && aliceSpliceStatus.session.fundingParams.localOutputs.isEmpty() -> actionsAlice2.has<ChannelAction.Storage.StoreOutgoingPayment.ViaSpliceCpfp>()
                else -> {}
            }
            if (alice1.staticParams.useZeroConf) {
                assertEquals(actionsAlice2.hasOutgoingMessage<SpliceLocked>().fundingTxId, txSigsAlice.txId)
            }
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(txSigsAlice))
            assertEquals(actionsBob2.size, 2)
            assertEquals(actionsBob2.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.FundingTx).txid, txSigsBob.txId)
            actionsBob2.has<ChannelAction.Storage.StoreState>()

            assertEquals(alice.commitments.active.size + 1, alice2.commitments.active.size)
            assertEquals(bob.commitments.active.size + 1, bob2.commitments.active.size)

            assertTrue { alice2.commitments.isMoreRecent(alice.commitments) }
            assertTrue { bob2.commitments.isMoreRecent(bob.commitments) }

            assertIs<LNChannel<Normal>>(alice2)
            assertIs<LNChannel<Normal>>(bob2)
            return Pair(alice2, bob2)
        }

        private fun createWalletWithFunds(keyManager: KeyManager, amounts: List<Satoshi>): List<WalletState.Utxo> {
            val script = keyManager.swapInOnChainWallet.swapInProtocol.pubkeyScript
            return amounts.map { amount ->
                val txIn = listOf(TxIn(OutPoint(TxId(Lightning.randomBytes32()), 2), 0))
                val txOut = listOf(TxOut(amount, script), TxOut(150.sat, Script.pay2wpkh(randomKey().publicKey())))
                val parentTx = Transaction(2, txIn, txOut, 0)
                WalletState.Utxo(parentTx, 0, 42)
            }
        }

        fun disconnect(alice: LNChannel<Normal>, bob: LNChannel<Normal>): Triple<LNChannel<Syncing>, LNChannel<Syncing>, ChannelReestablish> {
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.Disconnected)
            val (bob1, actionsBob1) = bob.process(ChannelCommand.Disconnected)
            assertIs<Offline>(alice1.state)
            assertTrue(actionsAlice1.isEmpty())
            assertIs<Offline>(bob1.state)
            assertTrue(actionsBob1.isEmpty())

            val aliceInit = Init(alice1.commitments.params.localParams.features)
            val bobInit = Init(bob1.commitments.params.localParams.features)
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Connected(aliceInit, bobInit))
            assertIs<LNChannel<Syncing>>(alice2)
            val channelReestablish = actionsAlice2.findOutgoingMessage<ChannelReestablish>()
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.Connected(bobInit, aliceInit))
            assertIs<LNChannel<Syncing>>(bob2)
            assertTrue(actionsBob2.isEmpty())
            return Triple(alice2, bob2, channelReestablish)
        }

        /** Full remote commit resolution from tx detection to channel close */
        private fun handleRemoteClose(channel1: LNChannel<Closing>, actions1: List<ChannelAction>, commitment: Commitment, remoteCommitTx: Transaction) {
            assertIs<Closing>(channel1.state)
            assertEquals(0, commitment.remoteCommit.spec.htlcs.size, "this helper only supports remote-closing without htlcs")

            // Spend our outputs from the remote commitment.
            actions1.has<ChannelAction.Storage.StoreState>()
            val claimRemoteDelayedOutputTx = actions1.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.ClaimRemoteDelayedOutputTx)
            Transaction.correctlySpends(claimRemoteDelayedOutputTx, remoteCommitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            actions1.hasWatchConfirmed(remoteCommitTx.txid)
            actions1.hasWatchConfirmed(claimRemoteDelayedOutputTx.txid)

            // Remote commit confirms.
            val (channel2, actions2) = channel1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(channel1.channelId, BITCOIN_TX_CONFIRMED(remoteCommitTx), channel1.currentBlockHeight, 42, remoteCommitTx)))
            assertIs<Closing>(channel2.state)
            assertEquals(actions2.size, 1)
            actions2.has<ChannelAction.Storage.StoreState>()

            // Claim main output confirms.
            val (channel3, actions3) = channel2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(channel1.channelId, BITCOIN_TX_CONFIRMED(claimRemoteDelayedOutputTx), channel2.currentBlockHeight, 43, claimRemoteDelayedOutputTx)))
            assertIs<Closed>(channel3.state)
            assertEquals(actions3.size, 2)
            actions3.has<ChannelAction.Storage.StoreState>()
            actions3.has<ChannelAction.Storage.SetLocked>()
        }

        private fun handlePreviousRemoteClose(alice1: LNChannel<Normal>, bobCommitTx: Transaction) {
            // Alice detects the force-close.
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventSpent(alice1.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
            assertIs<Closing>(alice2.state)
            // Alice attempts to force-close and in parallel puts a watch on the remote commit.
            assertEquals(actionsAlice2.size, 7)
            val localCommit = actionsAlice2.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.CommitTx)
            assertEquals(localCommit.txid, alice1.commitments.active.first().localCommit.publishableTxs.commitTx.tx.txid)
            val claimMain = actionsAlice2.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.ClaimLocalDelayedOutputTx)
            actionsAlice2.hasWatchConfirmed(localCommit.txid)
            actionsAlice2.hasWatchConfirmed(claimMain.txid)
            assertEquals(actionsAlice2.hasWatchConfirmed(bobCommitTx.txid).event, BITCOIN_ALTERNATIVE_COMMIT_TX_CONFIRMED)
            actionsAlice2.has<ChannelAction.Storage.StoreState>()
            actionsAlice2.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()

            // Bob's commitment confirms.
            val (alice3, actionsAlice3) = alice2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice2.channelId, BITCOIN_ALTERNATIVE_COMMIT_TX_CONFIRMED, alice2.currentBlockHeight, 43, bobCommitTx)))
            assertIs<LNChannel<Closing>>(alice3)
            // Alice cleans up the commitments.
            assertTrue(alice2.commitments.active.size > 1)
            assertEquals(1, alice3.commitments.active.size)
            assertEquals(alice3.commitments.active.first().fundingTxId, bobCommitTx.txIn.first().outPoint.txid)
            // And processes the remote commit.
            actionsAlice3.doesNotHave<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()
            handleRemoteClose(alice3, actionsAlice3, alice3.commitments.active.first(), bobCommitTx)
        }

        private fun handleCurrentRevokedRemoteClose(alice1: LNChannel<Normal>, bobCommitTx: Transaction) {
            // Alice detects the revoked force-close.
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventSpent(alice1.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
            assertIs<Closing>(alice2.state)
            assertEquals(actionsAlice2.size, 9)
            val claimMain = actionsAlice2.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.ClaimRemoteDelayedOutputTx)
            Transaction.correctlySpends(claimMain, bobCommitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            val claimRemotePenalty = actionsAlice2.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.MainPenaltyTx)
            Transaction.correctlySpends(claimRemotePenalty, bobCommitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            val watchCommitConfirmed = actionsAlice2.hasWatchConfirmed(bobCommitTx.txid)
            actionsAlice2.hasWatchConfirmed(claimMain.txid)
            val watchSpent = actionsAlice2.hasWatch<WatchSpent>()
            assertEquals(watchSpent.txId, claimRemotePenalty.txIn.first().outPoint.txid)
            assertEquals(watchSpent.outputIndex, claimRemotePenalty.txIn.first().outPoint.index.toInt())
            assertEquals(actionsAlice2.find<ChannelAction.Storage.GetHtlcInfos>().revokedCommitTxId, bobCommitTx.txid)
            actionsAlice2.hasOutgoingMessage<Error>()
            actionsAlice2.has<ChannelAction.Storage.StoreState>()
            actionsAlice2.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()

            // Bob's commitment confirms.
            val (alice3, actionsAlice3) = alice2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice2.channelId, watchCommitConfirmed.event, alice2.currentBlockHeight, 43, bobCommitTx)))
            assertIs<Closing>(alice3.state)
            actionsAlice3.has<ChannelAction.Storage.StoreState>()

            // Alice's transactions confirm.
            val (alice4, actionsAlice4) = alice3.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice3.channelId, BITCOIN_TX_CONFIRMED(claimMain), alice3.currentBlockHeight, 44, claimMain)))
            assertIs<Closing>(alice4.state)
            assertEquals(actionsAlice4.size, 1)
            actionsAlice4.has<ChannelAction.Storage.StoreState>()
            val (alice5, actionsAlice5) = alice4.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice4.channelId, BITCOIN_TX_CONFIRMED(claimRemotePenalty), alice4.currentBlockHeight, 45, claimRemotePenalty)))
            assertIs<Closed>(alice5.state)
            actionsAlice5.has<ChannelAction.Storage.StoreState>()
            actionsAlice5.has<ChannelAction.Storage.SetLocked>()
        }

        private fun handlePreviousRevokedRemoteClose(alice1: LNChannel<Normal>, bobCommitTx: Transaction) {
            // Alice detects that the remote force-close is not based on the latest funding transaction.
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventSpent(alice1.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
            assertIs<Closing>(alice2.state)
            assertEquals(actionsAlice2.size, 7)
            // Alice attempts to force-close and in parallel puts a watch on the remote commit.
            val localCommit = actionsAlice2.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.CommitTx)
            assertEquals(localCommit.txid, alice1.commitments.active.first().localCommit.publishableTxs.commitTx.tx.txid)
            val claimMain = actionsAlice2.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.ClaimLocalDelayedOutputTx)
            actionsAlice2.hasWatchConfirmed(localCommit.txid)
            actionsAlice2.hasWatchConfirmed(claimMain.txid)
            assertEquals(actionsAlice2.hasWatchConfirmed(bobCommitTx.txid).event, BITCOIN_ALTERNATIVE_COMMIT_TX_CONFIRMED)
            actionsAlice2.has<ChannelAction.Storage.StoreState>()
            actionsAlice2.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()

            // Bob's revoked commitment confirms.
            val (alice3, actionsAlice3) = alice2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice2.channelId, BITCOIN_ALTERNATIVE_COMMIT_TX_CONFIRMED, alice2.currentBlockHeight, 43, bobCommitTx)))
            assertIs<Closing>(alice3.state)
            assertEquals(actionsAlice3.size, 8)
            val claimMainPenalty = actionsAlice3.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.ClaimRemoteDelayedOutputTx)
            Transaction.correctlySpends(claimMainPenalty, bobCommitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            val claimRemotePenalty = actionsAlice3.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.MainPenaltyTx)
            Transaction.correctlySpends(claimRemotePenalty, bobCommitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            assertIs<BITCOIN_TX_CONFIRMED>(actionsAlice3.hasWatchConfirmed(bobCommitTx.txid).event)
            actionsAlice3.hasWatchConfirmed(claimMainPenalty.txid)
            val watchSpent = actionsAlice3.hasWatch<WatchSpent>()
            assertEquals(watchSpent.txId, claimRemotePenalty.txIn.first().outPoint.txid)
            assertEquals(watchSpent.outputIndex, claimRemotePenalty.txIn.first().outPoint.index.toInt())
            assertEquals(actionsAlice3.find<ChannelAction.Storage.GetHtlcInfos>().revokedCommitTxId, bobCommitTx.txid)
            actionsAlice3.hasOutgoingMessage<Error>()
            actionsAlice3.has<ChannelAction.Storage.StoreState>()

            // Alice's transactions confirm.
            val (alice4, actionsAlice4) = alice3.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice3.channelId, BITCOIN_TX_CONFIRMED(bobCommitTx), alice3.currentBlockHeight, 43, bobCommitTx)))
            assertEquals(actionsAlice4.size, 1)
            actionsAlice4.has<ChannelAction.Storage.StoreState>()
            val (alice5, actionsAlice5) = alice4.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice4.channelId, BITCOIN_TX_CONFIRMED(claimMainPenalty), alice4.currentBlockHeight, 44, claimMainPenalty)))
            assertEquals(actionsAlice5.size, 1)
            actionsAlice5.has<ChannelAction.Storage.StoreState>()
            val (alice6, actionsAlice6) = alice5.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice5.channelId, BITCOIN_TX_CONFIRMED(claimRemotePenalty), alice5.currentBlockHeight, 45, claimRemotePenalty)))
            assertIs<Closed>(alice6.state)
            actionsAlice6.has<ChannelAction.Storage.StoreState>()
            actionsAlice6.has<ChannelAction.Storage.SetLocked>()
        }
    }

}
