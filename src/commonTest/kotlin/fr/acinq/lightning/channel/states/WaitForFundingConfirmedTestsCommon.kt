package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.Feature
import fr.acinq.lightning.Features
import fr.acinq.lightning.Lightning.randomBytes
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.electrum.UnspentItem
import fr.acinq.lightning.blockchain.electrum.WalletState
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*

import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.*
import kotlin.test.*

class WaitForFundingConfirmedTestsCommon : LightningTestSuite() {

    @Test
    fun `recv TxSignatures`() {
        val (alice, bob, txSigsBob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<LNChannel<WaitForFundingConfirmed>>(alice1)
        assertIs<FullySignedSharedTransaction>(alice1.state.latestFundingTx.sharedTx)
        assertEquals(actionsAlice1.size, 2)
        val fundingTx = actionsAlice1.find<ChannelAction.Blockchain.PublishTx>().tx
        assertEquals(fundingTx.txid, alice1.state.latestFundingTx.sharedTx.localSigs.txId)
        actionsAlice1.has<ChannelAction.Storage.StoreState>()
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(alice1.state.latestFundingTx.sharedTx.localSigs))
        assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
        assertIs<FullySignedSharedTransaction>(bob1.state.latestFundingTx.sharedTx)
        assertEquals(actionsBob1.size, 2)
        actionsBob1.hasPublishTx(fundingTx)
        actionsBob1.has<ChannelAction.Storage.StoreState>()
    }

    @Test
    fun `recv TxSignatures -- duplicate`() {
        val (alice, _, txSigsBob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, _) = alice.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<LNChannel<WaitForFundingConfirmed>>(alice1)
        assertIs<FullySignedSharedTransaction>(alice1.state.latestFundingTx.sharedTx)
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(txSigsBob))
        assertEquals(alice1, alice2)
        assertTrue(actionsAlice2.isEmpty())
    }

    @Test
    fun `recv TxSignatures -- invalid`() {
        val (alice, _, txSigsBob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(txSigsBob.copy(witnesses = listOf(Script.witnessPay2wpkh(randomKey().publicKey(), randomBytes(72).byteVector())))))
        // Alice sends an error, but stays in the same state because the funding tx may still confirm.
        assertEquals(actionsAlice1.size, 1)
        actionsAlice1.findOutgoingMessage<Warning>()
        assertEquals(alice, alice1)
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK`() {
        val (alice, bob, txSigsBob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<LNChannel<WaitForFundingConfirmed>>(alice1)
        val fundingTx = actionsAlice1.find<ChannelAction.Blockchain.PublishTx>().tx
        run {
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
            assertIs<LNChannel<WaitForChannelReady>>(alice2)
            actionsAlice2.hasOutgoingMessage<ChannelReady>()
            actionsAlice2.has<ChannelAction.Storage.SetConfirmationStatus>()
            actionsAlice2.has<ChannelAction.Storage.StoreState>()
            val watch = actionsAlice2.hasWatch<WatchSpent>()
            assertEquals(watch.event, BITCOIN_FUNDING_SPENT)
            assertEquals(watch.txId, fundingTx.txid)
            assertEquals(watch.outputIndex.toLong(), alice.state.commitments.latest.commitInput.outPoint.index)
        }
        run {
            val (bob1, _) = bob.process(ChannelCommand.MessageReceived(alice1.state.latestFundingTx.sharedTx.localSigs))
            assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
            assertIs<LNChannel<WaitForChannelReady>>(bob2)
            actionsBob2.hasOutgoingMessage<ChannelReady>()
            actionsBob2.has<ChannelAction.Storage.SetConfirmationStatus>()
            actionsBob2.has<ChannelAction.Storage.StoreState>()
            val watch = actionsBob2.hasWatch<WatchSpent>()
            assertEquals(watch.event, BITCOIN_FUNDING_SPENT)
            assertEquals(watch.txId, fundingTx.txid)
            assertEquals(watch.outputIndex.toLong(), bob.state.commitments.latest.commitInput.outPoint.index)
        }
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK -- without remote sigs`() {
        val (alice, _, _) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        assertIs<PartiallySignedSharedTransaction>(alice.state.latestFundingTx.sharedTx)
        val fundingTx = alice.state.latestFundingTx.sharedTx.tx.buildUnsignedTx()
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
        assertIs<LNChannel<WaitForChannelReady>>(alice1)
        actionsAlice1.hasOutgoingMessage<ChannelReady>()
        actionsAlice1.has<ChannelAction.Storage.SetConfirmationStatus>()
        actionsAlice1.has<ChannelAction.Storage.StoreState>()
        val watch = actionsAlice1.hasWatch<WatchSpent>()
        assertEquals(watch.event, BITCOIN_FUNDING_SPENT)
        assertEquals(watch.txId, fundingTx.txid)
        assertEquals(watch.outputIndex.toLong(), alice.state.commitments.latest.commitInput.outPoint.index)
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK -- rbf in progress`() {
        val (alice, bob, txSigsBob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (_, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(txSigsBob))
        val fundingTx = actionsAlice1.find<ChannelAction.Blockchain.PublishTx>().tx
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(TxInitRbf(alice.state.channelId, 0, FeeratePerKw(6000.sat), TestConstants.aliceFundingAmount)))
        assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
        assertIs<WaitForFundingConfirmed.Companion.RbfStatus.InProgress>(bob1.state.rbfStatus)
        assertEquals(actionsBob1.size, 1)
        actionsBob1.hasOutgoingMessage<TxAckRbf>()
        // The funding transaction confirms while the RBF attempt is in progress.
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
        assertIs<LNChannel<WaitForChannelReady>>(bob2)
        val watch = actionsBob2.hasWatch<WatchSpent>()
        assertEquals(watch.event, BITCOIN_FUNDING_SPENT)
        assertEquals(watch.txId, fundingTx.txid)
        assertEquals(watch.outputIndex.toLong(), bob.state.commitments.latest.commitInput.outPoint.index)
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK -- previous funding tx`() {
        val (alice, bob, txSigsBob, walletAlice) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val fundingTxId1 = alice.state.commitments.latest.fundingTxId
        val (alice1, bob1) = rbf(alice, bob, txSigsBob, walletAlice)
        run {
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, alice.state.latestFundingTx.sharedTx.tx.buildUnsignedTx())))
            actionsBob2.has<ChannelAction.Storage.SetConfirmationStatus>()
            assertIs<LNChannel<WaitForChannelReady>>(bob2)
            val watch = actionsBob2.hasWatch<WatchSpent>()
            assertEquals(watch.event, BITCOIN_FUNDING_SPENT)
            assertEquals(watch.txId, fundingTxId1)
            assertEquals(watch.outputIndex.toLong(), bob.state.commitments.latest.commitInput.outPoint.index)
        }
        run {
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, alice.state.latestFundingTx.sharedTx.tx.buildUnsignedTx())))
            actionsAlice2.has<ChannelAction.Storage.SetConfirmationStatus>()
            assertIs<LNChannel<WaitForChannelReady>>(alice2)
            val watch = actionsAlice2.hasWatch<WatchSpent>()
            assertEquals(watch.event, BITCOIN_FUNDING_SPENT)
            assertEquals(watch.txId, fundingTxId1)
            assertEquals(watch.outputIndex.toLong(), bob.state.commitments.latest.commitInput.outPoint.index)
        }
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK -- after restart`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val fundingTx = alice.state.latestFundingTx.sharedTx.tx.buildUnsignedTx()
        run {
            val (alice1, _) = LNChannel(alice.ctx, WaitForInit).process(ChannelCommand.Restore(alice.state))
                .also { (state, actions) ->
                    assertIs<LNChannel<Offline>>(state)
                    assertEquals(actions.findWatch<WatchConfirmed>().txId, fundingTx.txid)
                }
            val (_, _) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
                .also { (state, actions) ->
                    assertIs<LNChannel<Offline>>(state)
                    actions.has<ChannelAction.Storage.SetConfirmationStatus>()
                    actions.hasWatchFundingSpent(fundingTx.txid)
                    actions.has<ChannelAction.Storage.StoreState>()
                }
        }
        run {
            val (bob1, _) = LNChannel(bob.ctx, WaitForInit).process(ChannelCommand.Restore(bob.state))
                .also { (state, actions) ->
                    assertIs<LNChannel<Offline>>(state)
                    assertEquals(actions.findWatch<WatchConfirmed>().txId, fundingTx.txid)
                }
            val (_, _) = bob1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
                .also { (state, actions) ->
                    assertIs<LNChannel<Offline>>(state)
                    actions.has<ChannelAction.Storage.SetConfirmationStatus>()
                    actions.hasWatchFundingSpent(fundingTx.txid)
                    actions.has<ChannelAction.Storage.StoreState>()
                }
        }
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK -- after restart -- previous funding tx`() {
        val (alice, bob, txSigsBob, walletAlice) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, bob1) = rbf(alice, bob, txSigsBob, walletAlice)
        val fundingTx1 = alice1.state.previousFundingTxs.first().signedTx!!
        val fundingTx2 = alice1.state.latestFundingTx.signedTx!!
        run {
            val (alice2, _) = LNChannel(alice.ctx, WaitForInit).process(ChannelCommand.Restore(alice1.state))
                .also { (state, actions) ->
                    assertIs<LNChannel<Offline>>(state)
                    assertEquals(actions.size, 4)
                    actions.hasPublishTx(fundingTx1)
                    actions.hasPublishTx(fundingTx2)
                    assertEquals(actions.findWatches<WatchConfirmed>().map { it.txId }.toSet(), setOf(fundingTx1.txid, fundingTx2.txid))
                }
            val (_, _) = alice2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx1)))
                .also { (state, actions) ->
                    assertIs<LNChannel<Offline>>(state)
                    actions.has<ChannelAction.Storage.SetConfirmationStatus>()
                    actions.hasWatchFundingSpent(fundingTx1.txid)
                    actions.has<ChannelAction.Storage.StoreState>()
                }
        }
        run {
            val (bob2, _) = LNChannel(bob.ctx, WaitForInit).process(ChannelCommand.Restore(bob1.state))
                .also { (state, actions) ->
                    assertIs<LNChannel<Offline>>(state)
                    // Bob doesn't have Alice's signatures for the latest funding tx, so he cannot re-publish it
                    assertContains(actions.findWatches<WatchConfirmed>().map { it.txId }, fundingTx1.txid)
                    assertContains(actions.findWatches<WatchConfirmed>().map { it.txId }, fundingTx2.txid)
                }
            val (_, _) = bob2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx1)))
                .also { (state, actions) ->
                    assertIs<LNChannel<Offline>>(state)
                    actions.has<ChannelAction.Storage.SetConfirmationStatus>()
                    actions.hasWatchFundingSpent(fundingTx1.txid)
                    actions.has<ChannelAction.Storage.StoreState>()
                }
        }
    }

    @Test
    fun `recv TxInitRbf`() {
        val (alice, bob, txSigsBob, walletAlice) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, bob1) = rbf(alice, bob, txSigsBob, walletAlice)
        assertEquals(alice1.state.previousFundingTxs.size, 1)
        assertEquals(bob1.state.previousFundingTxs.size, 1)
        assertTrue(alice1.state.commitments.latest.fundingTxId != alice.state.commitments.latest.fundingTxId)
        assertTrue(bob1.state.commitments.latest.fundingTxId != bob.state.commitments.latest.fundingTxId)
        assertEquals(alice1.state.commitments.latest.fundingTxId, bob1.state.commitments.latest.fundingTxId)
    }

    @Test
    fun `recv TxInitRbf -- invalid feerate`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(TxInitRbf(alice.state.channelId, 0, TestConstants.feeratePerKw, alice.state.latestFundingTx.fundingParams.localAmount)))
        assertEquals(actions1.size, 1)
        assertEquals(actions1.hasOutgoingMessage<TxAbort>().toAscii(), InvalidRbfFeerate(alice.state.channelId, TestConstants.feeratePerKw, TestConstants.feeratePerKw * 25 / 24).message)
        val (bob2, actions2) = bob1.process(ChannelCommand.MessageReceived(TxAbort(alice.state.channelId, "acking tx_abort")))
        assertEquals(bob2, bob)
        assertTrue(actions2.isEmpty())
    }

    @Test
    fun `recv TxInitRbf -- invalid push amount`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(TxInitRbf(alice.state.channelId, 0, TestConstants.feeratePerKw * 1.25, TestConstants.alicePushAmount.truncateToSatoshi() - 1.sat)))
        assertEquals(actions1.size, 1)
        assertEquals(actions1.hasOutgoingMessage<TxAbort>().toAscii(), InvalidPushAmount(alice.state.channelId, TestConstants.alicePushAmount, TestConstants.alicePushAmount - 1000.msat).message)
        val (bob2, actions2) = bob1.process(ChannelCommand.MessageReceived(TxAbort(alice.state.channelId, "acking tx_abort")))
        assertEquals(bob2, bob)
        assertTrue(actions2.isEmpty())
    }

    @Test
    fun `recv TxInitRbf -- failed rbf attempt`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(TxInitRbf(alice.state.channelId, 0, TestConstants.feeratePerKw * 1.25, alice.state.latestFundingTx.fundingParams.localAmount)))
        assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
        assertIs<WaitForFundingConfirmed.Companion.RbfStatus.InProgress>(bob1.state.rbfStatus)
        assertEquals(actions1.size, 1)
        actions1.hasOutgoingMessage<TxAckRbf>()
        val txAddInput = alice.state.latestFundingTx.sharedTx.tx.localInputs.first().run { TxAddInput(alice.channelId, serialId, previousTx, previousTxOutput, sequence) }
        val (bob2, actions2) = bob1.process(ChannelCommand.MessageReceived(txAddInput))
        assertEquals(actions2.size, 1)
        actions2.hasOutgoingMessage<TxAddInput>()
        val (bob3, actions3) = bob2.process(ChannelCommand.MessageReceived(TxAbort(alice.state.channelId, "changed my mind")))
        assertIs<LNChannel<WaitForFundingConfirmed>>(bob3)
        assertEquals(bob3.state.rbfStatus, WaitForFundingConfirmed.Companion.RbfStatus.None)
        assertEquals(actions3.size, 1)
        actions3.hasOutgoingMessage<TxAbort>()
    }

    @Test
    fun `recv ChannelReady`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val channelReadyAlice = ChannelReady(alice.state.channelId, randomKey().publicKey())
        val channelReadyBob = ChannelReady(bob.state.channelId, randomKey().publicKey())
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(channelReadyBob))
        assertIs<LNChannel<WaitForFundingConfirmed>>(alice1)
        assertEquals(alice1.state.deferred, channelReadyBob)
        assertTrue(actionsAlice1.isEmpty())
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(channelReadyAlice))
        assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
        assertEquals(bob1.state.deferred, channelReadyAlice)
        assertTrue(actionsBob1.isEmpty())
    }

    @Test
    fun `recv ChannelReady -- no remote contribution`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat, alicePushAmount = 0.msat)
        val channelReadyAlice = ChannelReady(alice.state.channelId, randomKey().publicKey())
        val channelReadyBob = ChannelReady(bob.state.channelId, randomKey().publicKey())
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(channelReadyBob))
        assertIs<LNChannel<WaitForFundingConfirmed>>(alice1)
        assertEquals(alice1.state.deferred, channelReadyBob)
        assertTrue(actionsAlice1.isEmpty())
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(channelReadyAlice))
        assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
        assertEquals(bob1.state.deferred, channelReadyAlice)
        assertTrue(actionsBob1.isEmpty())
    }

    @Test
    fun `recv Error`() {
        val (_, bob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(Error(bob.state.channelId, "oops")))
        assertIs<LNChannel<Closing>>(bob1)
        assertNotNull(bob1.state.localCommitPublished)
        actions1.hasPublishTx(bob.state.commitments.latest.localCommit.publishableTxs.commitTx.tx)
        assertEquals(2, actions1.findWatches<WatchConfirmed>().size) // commit tx + main output
    }

    @Test
    fun `recv Error -- previous funding tx confirms`() {
        val (alice, bob, txSigsBob, walletAlice) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val commitTxAlice1 = alice.state.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val commitTxBob1 = bob.state.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val fundingTxId1 = alice.state.commitments.latest.fundingTxId
        val (alice1, bob1) = rbf(alice, bob, txSigsBob, walletAlice)
        val commitTxAlice2 = alice1.state.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val commitTxBob2 = bob1.state.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val fundingTxId2 = alice1.state.commitments.latest.fundingTxId
        assertTrue(fundingTxId1 != fundingTxId2)
        assertTrue(commitTxAlice1.txid != commitTxAlice2.txid)
        assertTrue(commitTxBob1.txid != commitTxBob2.txid)
        run {
            // Bob receives an error and publishes his latest commitment.
            val (bob2, actions2) = bob1.process(ChannelCommand.MessageReceived(Error(bob.state.channelId, "oops")))
            assertIs<LNChannel<Closing>>(bob2)
            assertTrue(bob2.commitments.active.size > 1)
            actions2.hasPublishTx(commitTxBob2)
            val lcp1 = bob2.state.localCommitPublished
            assertNotNull(lcp1)
            assertTrue(lcp1.commitTx.txIn.map { it.outPoint.txid }.contains(fundingTxId2))
            // A previous funding transaction confirms, so Bob publishes the corresponding commit tx.
            val (bob3, actions3) = bob2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.state.channelId, BITCOIN_FUNDING_DEPTHOK, 50, 0, alice.state.latestFundingTx.sharedTx.tx.buildUnsignedTx())))
            assertIs<LNChannel<Closing>>(bob3)
            assertEquals(bob3.state.commitments.active.size, 1)
            actions3.hasPublishTx(commitTxBob1)
            val lcp2 = bob3.state.localCommitPublished
            assertNotNull(lcp2)
            assertTrue(lcp2.commitTx.txIn.map { it.outPoint.txid }.contains(fundingTxId1))
            // Alice publishes her commit tx, Bob reacts by spending his remote main output.
            val (bob4, actions4) = bob3.process(ChannelCommand.WatchReceived(WatchEventSpent(bob.state.channelId, BITCOIN_FUNDING_SPENT, commitTxAlice1)))
            assertIs<LNChannel<Closing>>(bob4)
            assertNotNull(bob4.state.localCommitPublished)
            assertNotNull(bob4.state.remoteCommitPublished)
            val claimMain = actions4.findPublishTxs().first()
            assertEquals(claimMain.txIn.first().outPoint.txid, commitTxAlice1.txid)
        }
        run {
            // Alice receives an error and publishes her latest commitment.
            val (alice2, actions2) = alice1.process(ChannelCommand.MessageReceived(Error(alice.state.channelId, "oops")))
            assertIs<LNChannel<Closing>>(alice2)
            assertTrue(alice2.commitments.active.size > 1)
            actions2.hasPublishTx(commitTxAlice2)
            val lcp1 = alice2.state.localCommitPublished
            assertNotNull(lcp1)
            assertTrue(lcp1.commitTx.txIn.map { it.outPoint.txid }.contains(fundingTxId2))
            // A previous funding transaction confirms, so Alice publishes the corresponding commit tx.
            val (alice3, actions3) = alice2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.state.channelId, BITCOIN_FUNDING_DEPTHOK, 50, 0, bob.state.latestFundingTx.sharedTx.tx.buildUnsignedTx())))
            assertIs<LNChannel<Closing>>(alice3)
            assertEquals(alice3.commitments.active.size, 1)
            actions3.hasPublishTx(commitTxAlice1)
            val lcp2 = alice3.state.localCommitPublished
            assertNotNull(lcp2)
            assertTrue(lcp2.commitTx.txIn.map { it.outPoint.txid }.contains(fundingTxId1))
            // Bob publishes his commit tx, Alice reacts by spending her remote main output.
            val (alice4, actions4) = alice3.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.state.channelId, BITCOIN_FUNDING_SPENT, commitTxBob1)))
            assertIs<LNChannel<Closing>>(alice4)
            assertNotNull(alice4.state.localCommitPublished)
            assertNotNull(alice4.state.remoteCommitPublished)
            val claimMain = actions4.findPublishTxs().first()
            assertEquals(claimMain.txIn.first().outPoint.txid, commitTxBob1.txid)
        }
    }

    @Test
    fun `recv CMD_CLOSE`() {
        val (alice, bob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        listOf(alice, bob).forEach { state ->
            val (state1, actions1) = state.process(ChannelCommand.ExecuteCommand(CMD_CLOSE(null, null)))
            assertEquals(state, state1)
            actions1.hasCommandError<CommandUnavailableInThisState>()
        }
    }

    @Test
    fun `recv CMD_FORCECLOSE`() {
        val (alice, bob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        listOf(alice, bob).forEach { state ->
            val (state1, actions1) = state.process(ChannelCommand.ExecuteCommand(CMD_FORCECLOSE))
            assertIs<LNChannel<Closing>>(state1)
            assertNotNull(state1.state.localCommitPublished)
            actions1.hasPublishTx(state1.state.localCommitPublished!!.commitTx)
            actions1.hasPublishTx(state1.state.localCommitPublished!!.claimMainDelayedOutputTx!!.tx)
            assertEquals(2, actions1.findWatches<WatchConfirmed>().size) // commit tx + main output
        }
    }

    @Test
    fun `recv CMD_FORCECLOSE -- nothing at stake`() {
        val (alice, bob) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat, alicePushAmount = 0.msat)
        val (bob1, actions1) = bob.process(ChannelCommand.ExecuteCommand(CMD_FORCECLOSE))
        assertIs<LNChannel<Aborted>>(bob1)
        assertEquals(1, actions1.size)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(ForcedLocalCommit(alice.state.channelId).message, error.toAscii())
    }

    @Test
    fun `recv CheckHtlcTimeout`() {
        val (alice, bob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        listOf(alice, bob).forEach { state ->
            run {
                val (state1, actions1) = state.process(ChannelCommand.CheckHtlcTimeout)
                assertEquals(state, state1)
                assertTrue(actions1.isEmpty())
            }
        }
    }

    @Test
    fun `recv Disconnected`() {
        val (alice, bob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.Disconnected)
        assertIs<LNChannel<Offline>>(alice1)
        assertTrue(actionsAlice1.isEmpty())
        val (bob1, actionsBob1) = bob.process(ChannelCommand.Disconnected)
        assertIs<LNChannel<Offline>>(bob1)
        assertTrue(actionsBob1.isEmpty())
    }

    companion object {
        data class Fixture(val alice: LNChannel<WaitForFundingConfirmed>, val bob: LNChannel<WaitForFundingConfirmed>, val txSigsBob: TxSignatures, val walletAlice: WalletState)

        fun init(
            channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs,
            aliceFeatures: Features = TestConstants.Alice.nodeParams.features,
            bobFeatures: Features = TestConstants.Bob.nodeParams.features,
            currentHeight: Int = TestConstants.defaultBlockHeight,
            aliceFundingAmount: Satoshi = TestConstants.aliceFundingAmount,
            bobFundingAmount: Satoshi = TestConstants.bobFundingAmount,
            alicePushAmount: MilliSatoshi = TestConstants.alicePushAmount,
            bobPushAmount: MilliSatoshi = TestConstants.bobPushAmount,
        ): Fixture {
            val (alice, commitAlice, bob, commitBob) = WaitForFundingSignedTestsCommon.init(channelType, aliceFeatures, bobFeatures, currentHeight, aliceFundingAmount, bobFundingAmount, alicePushAmount, bobPushAmount, zeroConf = false)
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(commitBob))
            assertIs<LNChannel<WaitForFundingConfirmed>>(alice1)
            assertEquals(actionsAlice1.findWatch<WatchConfirmed>().event, BITCOIN_FUNDING_DEPTHOK)
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(commitAlice))
            assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
            assertEquals(actionsBob1.findWatch<WatchConfirmed>().event, BITCOIN_FUNDING_DEPTHOK)
            val txSigs = actionsBob1.findOutgoingMessage<TxSignatures>()
            if (bob.staticParams.nodeParams.features.hasFeature(Feature.ChannelBackupClient)) {
                assertFalse(txSigs.channelData.isEmpty())
            }
            return Fixture(alice1, bob1, txSigs, alice.state.wallet)
        }

        fun rbf(alice: LNChannel<WaitForFundingConfirmed>, bob: LNChannel<WaitForFundingConfirmed>, txSigsBob: TxSignatures, walletAlice: WalletState): Pair<LNChannel<WaitForFundingConfirmed>, LNChannel<WaitForFundingConfirmed>> {
            val (alice0, _) = alice.process(ChannelCommand.MessageReceived(txSigsBob))
            assertIs<LNChannel<WaitForFundingConfirmed>>(alice0)
            val fundingParams0 = alice0.state.latestFundingTx.fundingParams
            val fundingTx0 = alice0.state.latestFundingTx.sharedTx
            assertIs<FullySignedSharedTransaction>(fundingTx0)
            // Alice adds a new input that increases her contribution and covers the additional fees.
            val command = run {
                val priv = alice.staticParams.nodeParams.keyManager.bip84PrivateKey(account = 1, addressIndex = 0)
                val parentTx = Transaction(2, listOf(TxIn(OutPoint(randomBytes32(), 1), 0)), listOf(TxOut(30_000.sat, Script.pay2wpkh(priv.publicKey()))), 0)
                val address = Bitcoin.computeP2WpkhAddress(priv.publicKey(), Block.RegtestGenesisBlock.hash)
                val wallet = WalletState(
                    walletAlice.addresses + (address to (walletAlice.addresses[address] ?: listOf()) + UnspentItem(parentTx.txid, 0, 30_000, 654321)),
                    walletAlice.parentTxs + (parentTx.txid to parentTx),
                )
                CMD_BUMP_FUNDING_FEE(fundingTx0.feerate * 1.1, fundingParams0.localAmount + 20_000.sat, wallet, fundingTx0.tx.lockTime + 1)
            }
            val (alice1, actionsAlice1) = alice0.process(ChannelCommand.ExecuteCommand(command))
            assertEquals(actionsAlice1.size, 1)
            val txInitRbf = actionsAlice1.findOutgoingMessage<TxInitRbf>()
            assertEquals(txInitRbf.fundingContribution, fundingParams0.localAmount + 20_000.sat)
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(txInitRbf))
            assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
            assertEquals(actionsBob1.size, 1)
            val txAckRbf = actionsBob1.findOutgoingMessage<TxAckRbf>()
            assertEquals(txAckRbf.fundingContribution, fundingParams0.remoteAmount) // the non-initiator doesn't change its contribution
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(txAckRbf))
            assertIs<LNChannel<WaitForFundingConfirmed>>(alice2)
            assertEquals(actionsAlice2.size, 1)
            // Alice and Bob build the next funding transaction.
            val (alice3, bob2) = completeInteractiveTxRbf(alice2, bob1, actionsAlice2.findOutgoingMessage())
            assertIs<LNChannel<WaitForFundingConfirmed>>(alice3)
            val fundingTx1 = alice3.state.latestFundingTx.sharedTx
            assertIs<FullySignedSharedTransaction>(fundingTx1)
            assertNotEquals(fundingTx0.signedTx.txid, fundingTx1.signedTx.txid)
            assertEquals(fundingTx1.signedTx.lockTime, fundingTx0.tx.lockTime + 1)
            assertEquals(alice3.state.commitments.latest.fundingAmount, alice.state.commitments.latest.fundingAmount + 20_000.sat)
            assertEquals(alice3.state.rbfStatus, WaitForFundingConfirmed.Companion.RbfStatus.None)
            assertEquals(bob2.state.rbfStatus, WaitForFundingConfirmed.Companion.RbfStatus.None)
            return Pair(alice3, bob2)
        }

        private fun completeInteractiveTxRbf(
            alice: LNChannel<WaitForFundingConfirmed>,
            bob: LNChannel<WaitForFundingConfirmed>,
            messageAlice: InteractiveTxMessage
        ): Pair<LNChannel<WaitForFundingConfirmed>, LNChannel<WaitForFundingConfirmed>> {
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(messageAlice))
            assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
            assertEquals(actionsBob1.size, 1)
            val messageBob = actionsBob1.findOutgoingMessage<InteractiveTxConstructionMessage>()
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(messageBob))
            assertIs<LNChannel<WaitForFundingConfirmed>>(alice1)
            return when (val txComplete = actionsAlice1.findOutgoingMessageOpt<TxComplete>()) {
                null -> {
                    assertEquals(actionsAlice1.size, 1)
                    completeInteractiveTxRbf(alice1, bob1, actionsAlice1.findOutgoingMessage())
                }
                else -> {
                    assertEquals(actionsAlice1.size, 2)
                    val commitSigAlice = actionsAlice1.findOutgoingMessage<CommitSig>()
                    val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(txComplete))
                    assertEquals(actionsBob2.size, 1)
                    val commitSigBob = actionsBob2.findOutgoingMessage<CommitSig>()
                    val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(commitSigBob))
                    assertEquals(actionsAlice2.size, 3)
                    assertTrue(actionsAlice2.hasOutgoingMessage<TxSignatures>().channelData.isEmpty())
                    actionsAlice2.has<ChannelAction.Storage.StoreState>()
                    val watchAlice = actionsAlice2.findWatch<WatchConfirmed>()
                    val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(commitSigAlice))
                    assertIs<LNChannel<WaitForFundingConfirmed>>(bob3)
                    assertEquals(actionsBob3.size, 3)
                    actionsBob3.has<ChannelAction.Storage.StoreState>()
                    val watchBob = actionsBob3.findWatch<WatchConfirmed>()
                    val txSigsBob = actionsBob3.findOutgoingMessage<TxSignatures>()
                    if (bob.staticParams.nodeParams.features.hasFeature(Feature.ChannelBackupClient)) {
                        assertFalse(txSigsBob.channelData.isEmpty())
                    }
                    val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(txSigsBob))
                    assertIs<LNChannel<WaitForFundingConfirmed>>(alice3)
                    assertEquals(actionsAlice3.size, 2)
                    actionsAlice3.has<ChannelAction.Storage.StoreState>()
                    val fundingTx = actionsAlice3.find<ChannelAction.Blockchain.PublishTx>().tx
                    assertEquals(fundingTx.hash, txSigsBob.txHash)
                    assertEquals(watchAlice.txId, fundingTx.txid)
                    assertEquals(watchBob.txId, fundingTx.txid)
                    Pair(alice3, bob3)
                }
            }
        }
    }

}
