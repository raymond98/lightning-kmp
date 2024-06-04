package fr.acinq.lightning.payment

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.*
import fr.acinq.lightning.Lightning.randomBytes
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomBytes64
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.crypto.RouteBlinding
import fr.acinq.lightning.crypto.sphinx.Sphinx.hash
import fr.acinq.lightning.db.InMemoryPaymentsDb
import fr.acinq.lightning.db.InboundLiquidityOutgoingPayment
import fr.acinq.lightning.db.IncomingPayment
import fr.acinq.lightning.db.IncomingPaymentsDb
import fr.acinq.lightning.io.OpenOrSplicePayment
import fr.acinq.lightning.io.SendOnTheFlyFundingMessage
import fr.acinq.lightning.io.WrappedChannelCommand
import fr.acinq.lightning.router.ChannelHop
import fr.acinq.lightning.router.NodeHop
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlin.test.*
import kotlin.time.Duration.Companion.milliseconds

class IncomingPaymentHandlerTestsCommon : LightningTestSuite() {

    @Test
    fun `add HTLC to channel commitments`() {
        var (alice, bob) = TestsHelper.reachNormal()
        val cmdAddHtlc = makeCmdAddHtlc(
            bob.staticParams.nodeParams.nodeId, defaultPaymentHash,
            makeMppPayload(100_000.msat, 150_000.msat, randomBytes32(), currentBlockHeight = alice.currentBlockHeight)
        )

        // Step 1: alice ---> update_add_htlc ---> bob

        var processResult = alice.processSameState(cmdAddHtlc)
        alice = processResult.first
        var actions = processResult.second
        assertEquals(2, actions.size)
        val add = actions.findOutgoingMessage<UpdateAddHtlc>()
        val aliceCmdSign = actions.findCommand<ChannelCommand.Commitment.Sign>()

        processResult = bob.processSameState(ChannelCommand.MessageReceived(add))
        bob = processResult.first
        actions = processResult.second
        assertTrue { actions.filterIsInstance<ChannelAction.Message.Send>().isEmpty() }

        assertTrue { alice.commitments.changes.localChanges.proposed.size == 1 }
        assertTrue { alice.commitments.changes.localChanges.signed.isEmpty() }
        assertTrue { alice.commitments.changes.localChanges.acked.isEmpty() }

        assertTrue { bob.commitments.changes.remoteChanges.proposed.size == 1 }
        assertTrue { bob.commitments.changes.remoteChanges.acked.isEmpty() }
        assertTrue { bob.commitments.changes.remoteChanges.signed.isEmpty() }

        // Step 2: alice ---> commitment_signed ---> bob

        processResult = alice.processSameState(aliceCmdSign)
        alice = processResult.first
        actions = processResult.second
        val aliceSig = actions.findOutgoingMessage<CommitSig>()

        processResult = bob.processSameState(ChannelCommand.MessageReceived(aliceSig))
        bob = processResult.first
        actions = processResult.second
        val bobRev = actions.findOutgoingMessage<RevokeAndAck>()
        val bobCmdSign = actions.findCommand<ChannelCommand.Commitment.Sign>()

        assertTrue { alice.commitments.changes.localChanges.proposed.isEmpty() }
        assertTrue { alice.commitments.changes.localChanges.signed.size == 1 }
        assertTrue { alice.commitments.changes.localChanges.acked.isEmpty() }

        assertTrue { bob.commitments.changes.remoteChanges.proposed.isEmpty() }
        assertTrue { bob.commitments.changes.remoteChanges.acked.size == 1 }
        assertTrue { bob.commitments.changes.remoteChanges.signed.isEmpty() }

        // Step 3: alice <--- revoke_and_ack <--- bob

        processResult = alice.processSameState(ChannelCommand.MessageReceived(bobRev))
        alice = processResult.first
        actions = processResult.second
        assertTrue { actions.filterIsInstance<ChannelAction.Message.Send>().isEmpty() }

        assertTrue { alice.commitments.changes.localChanges.proposed.isEmpty() }
        assertTrue { alice.commitments.changes.localChanges.signed.isEmpty() }
        assertTrue { alice.commitments.changes.localChanges.acked.size == 1 }

        assertTrue { bob.commitments.changes.remoteChanges.proposed.isEmpty() }
        assertTrue { bob.commitments.changes.remoteChanges.acked.size == 1 }
        assertTrue { bob.commitments.changes.remoteChanges.signed.isEmpty() }

        // Step 4: alice <--- commitment_signed <--- bob

        processResult = bob.processSameState(bobCmdSign)
        bob = processResult.first
        actions = processResult.second
        val bobSig = actions.findOutgoingMessage<CommitSig>()

        processResult = alice.processSameState(ChannelCommand.MessageReceived(bobSig))
        alice = processResult.first
        actions = processResult.second
        val aliceRev = actions.findOutgoingMessage<RevokeAndAck>()

        assertTrue { alice.commitments.changes.localChanges.proposed.isEmpty() }
        assertTrue { alice.commitments.changes.localChanges.signed.isEmpty() }
        assertTrue { alice.commitments.changes.localChanges.acked.isEmpty() }

        assertTrue { bob.commitments.changes.remoteChanges.proposed.isEmpty() }
        assertTrue { bob.commitments.changes.remoteChanges.acked.isEmpty() }
        assertTrue { bob.commitments.changes.remoteChanges.signed.size == 1 }

        // Step 5: alice ---> revoke_and_ack ---> bob

        processResult = bob.processSameState(ChannelCommand.MessageReceived(aliceRev))
        bob = processResult.first
        actions = processResult.second
        assertTrue { actions.filterIsInstance<ChannelAction.Message.Send>().isEmpty() }
        assertTrue { actions.filterIsInstance<ChannelAction.ProcessIncomingHtlc>().size == 1 }

        assertTrue { alice.commitments.changes.localChanges.proposed.isEmpty() }
        assertTrue { alice.commitments.changes.localChanges.signed.isEmpty() }
        assertTrue { alice.commitments.changes.localChanges.acked.isEmpty() }

        assertTrue { bob.commitments.changes.remoteChanges.proposed.isEmpty() }
        assertTrue { bob.commitments.changes.remoteChanges.acked.isEmpty() }
        assertTrue { bob.commitments.changes.remoteChanges.signed.isEmpty() }
    }

    @Test
    fun `receive multipart payment with single HTLC`() = runSuspendTest {
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(defaultAmount)
        checkDbPayment(incomingPayment, paymentHandler.db)
        val channelId = randomBytes32()
        val add = makeUpdateAddHtlc(12, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount, defaultAmount, paymentSecret))
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)

        assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
        val expected = ChannelCommand.Htlc.Settlement.Fulfill(add.id, incomingPayment.preimage, commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())

        assertEquals(result.incomingPayment.received, result.received)
        assertEquals(defaultAmount, result.received.amount)
        assertEquals(listOf(IncomingPayment.ReceivedWith.LightningPayment(defaultAmount, channelId, 12, null)), result.received.receivedWith)
        checkDbPayment(result.incomingPayment, paymentHandler.db)
    }

    @Test
    fun `receive multipart payment with multiple HTLCs`() = runSuspendTest {
        val channelId = randomBytes32()
        val (amount1, amount2) = Pair(100_000_000.msat, 50_000_000.msat)
        val totalAmount = amount1 + amount2
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(totalAmount)

        // Step 1 of 2:
        // - Alice sends first multipart htlc to Bob
        // - Bob doesn't accept the MPP set yet
        run {
            val add = makeUpdateAddHtlc(0, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 2:
        // - Alice sends second multipart htlc to Bob
        // - Bob now accepts the MPP set
        run {
            val add = makeUpdateAddHtlc(5, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
            val (expectedActions, expectedReceivedWith) = setOf(
                // @formatter:off
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(0, defaultPreimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount1, channelId, 0, fundingFee = null),
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(5, defaultPreimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount2, channelId, 5, fundingFee = null),
                // @formatter:on
            ).unzip()
            assertEquals(expectedActions.toSet(), result.actions.toSet())
            assertEquals(totalAmount, result.received.amount)
            assertEquals(expectedReceivedWith, result.received.receivedWith)
            checkDbPayment(result.incomingPayment, paymentHandler.db)
        }
    }

    @Test
    fun `receive multipart payment after disconnection`() = runSuspendTest {
        val channelId = randomBytes32()
        val (amount1, amount2) = Pair(75_000.msat, 75_000.msat)
        val totalAmount = amount1 + amount2
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(totalAmount)

        // Step 1: Alice sends first multipart htlc to Bob.
        val add1 = run {
            val add = makeUpdateAddHtlc(0, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertNull(result.incomingPayment.received)
            assertTrue(result.actions.isEmpty())
            add
        }

        // Step 2: Bob disconnects, and cleans up pending HTLCs.
        paymentHandler.purgePendingPayments()

        // Step 3: on reconnection, the HTLC from step 1 is processed again.
        run {
            val result = paymentHandler.process(add1, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertNull(result.incomingPayment.received)
            assertTrue(result.actions.isEmpty())
        }

        // Step 4: Alice sends second multipart htlc to Bob.
        run {
            val add = makeUpdateAddHtlc(1, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
            val (expectedActions, expectedReceivedWith) = setOf(
                // @formatter:off
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(0, defaultPreimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount1, channelId, 0, fundingFee = null),
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(1, defaultPreimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount2, channelId, 1, fundingFee = null),
                // @formatter:on
            ).unzip()
            assertEquals(expectedActions.toSet(), result.actions.toSet())
            assertEquals(totalAmount, result.received.amount)
            assertEquals(expectedReceivedWith, result.received.receivedWith)
            checkDbPayment(result.incomingPayment, paymentHandler.db)
        }
    }

    @Test
    fun `receive will_add_htlc`() = runSuspendTest {
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(defaultAmount)
        checkDbPayment(incomingPayment, paymentHandler.db)
        val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount, defaultAmount, paymentSecret))
        val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
        assertEquals(1, result.actions.size)
        val openOrSplice = result.actions.first()
        assertIs<OpenOrSplicePayment>(openOrSplice)
        assertEquals(incomingPayment.preimage, openOrSplice.preimage)
        assertEquals(defaultAmount, openOrSplice.paymentAmount)
        assertTrue(defaultAmount < openOrSplice.requestedAmount)
        assertEquals(TestConstants.fundingRates.fundingRates.first(), openOrSplice.fundingLease)
        // We don't update the payments DB: we're waiting to receive HTLCs after the open/splice.
        assertNull(paymentHandler.db.getIncomingPayment(incomingPayment.paymentHash)?.received)
    }

    @Test
    fun `receive two evenly-split will_add_htlc`() = runSuspendTest {
        val amount = 50_000_000.msat
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(amount * 2)
        checkDbPayment(incomingPayment, paymentHandler.db)

        // Step 1 of 2:
        //  - Alice sends first will_add_htlc to Bob
        //  - Bob doesn't trigger the open/splice yet
        run {
            val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount, amount * 2, paymentSecret))
            val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 2:
        //  - Alice sends second will_add_htlc to Bob
        //  - Bob trigger an open/splice
        run {
            val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount, amount * 2, paymentSecret))
            val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertEquals(1, result.actions.size)
            val openOrSplice = result.actions.first() as OpenOrSplicePayment
            assertEquals(incomingPayment.preimage, openOrSplice.preimage)
            assertEquals(amount * 2, openOrSplice.paymentAmount)
            assertNull(paymentHandler.db.getIncomingPayment(incomingPayment.paymentHash)?.received)
        }
    }

    @Test
    fun `receive two unevenly-split will_add_htlc`() = runSuspendTest {
        val (amount1, amount2) = Pair(50_000_000.msat, 75_000_000.msat)
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(amount1 + amount2)
        checkDbPayment(incomingPayment, paymentHandler.db)
        // The sender overpays the total_amount, which is ok.
        val totalAmount = amount1 + amount2 + 10_000_000.msat

        // Step 1 of 2:
        //  - Alice sends first will_add_htlc to Bob
        //  - Bob doesn't trigger the open/splice yet
        run {
            val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 2:
        //  - Alice sends second will_add_htlc to Bob
        //  - Bob trigger an open/splice
        run {
            val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2 + 10_000_000.msat, totalAmount, paymentSecret))
            val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertEquals(1, result.actions.size)
            val openOrSplice = result.actions.first() as OpenOrSplicePayment
            assertEquals(incomingPayment.preimage, openOrSplice.preimage)
            assertEquals(totalAmount, openOrSplice.paymentAmount)
            assertNull(paymentHandler.db.getIncomingPayment(incomingPayment.paymentHash)?.received)
        }
    }

    @Test
    fun `receive trampoline will_add_htlc`() = runSuspendTest {
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(defaultAmount)
        checkDbPayment(incomingPayment, paymentHandler.db)
        val willAddHtlc = run {
            // We simulate a trampoline-relay with a dummy channel hop between the liquidity provider and the wallet.
            val (amount, expiry, trampolineOnion) = OutgoingPaymentPacket.buildPacket(
                incomingPayment.paymentHash,
                listOf(NodeHop(TestConstants.Alice.nodeParams.nodeId, TestConstants.Bob.nodeParams.nodeId, CltvExpiryDelta(144), 0.msat)),
                makeMppPayload(defaultAmount, defaultAmount, paymentSecret),
                null
            )
            assertTrue(trampolineOnion.packet.payload.size() < 500)
            makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, PaymentOnion.FinalPayload.Standard.createTrampolinePayload(amount, amount, expiry, randomBytes32(), trampolineOnion.packet))
        }
        val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
        assertEquals(1, result.actions.size)
        val openOrSplice = result.actions.first()
        assertIs<OpenOrSplicePayment>(openOrSplice)
        assertEquals(incomingPayment.preimage, openOrSplice.preimage)
        assertEquals(defaultAmount, openOrSplice.paymentAmount)
        assertTrue(defaultAmount < openOrSplice.requestedAmount)
        assertEquals(TestConstants.fundingRates.fundingRates.first(), openOrSplice.fundingLease)
        assertNull(paymentHandler.db.getIncomingPayment(incomingPayment.paymentHash)?.received)
    }

    @Test
    fun `receive will_add_htlc with an unknown payment hash`() = runSuspendTest {
        val (paymentHandler, _, paymentSecret) = createFixture(defaultAmount)
        val willAddHtlc = makeWillAddHtlc(paymentHandler, randomBytes32(), makeMppPayload(defaultAmount, defaultAmount, paymentSecret))
        val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        assertNull(result.incomingPayment)
        val failure = OutgoingPaymentPacket.buildWillAddHtlcFailure(paymentHandler.nodeParams.nodePrivateKey, willAddHtlc, IncorrectOrUnknownPaymentDetails(defaultAmount, TestConstants.defaultBlockHeight.toLong()))
        assertIs<WillFailHtlc>(failure)
        assertEquals(listOf(SendOnTheFlyFundingMessage(failure)), result.actions)
    }

    @Test
    fun `receive will_add_htlc with an incorrect payment secret`() = runSuspendTest {
        val (paymentHandler, incomingPayment, _) = createFixture(defaultAmount)
        val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount, defaultAmount, randomBytes32()))
        val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        assertEquals(incomingPayment, result.incomingPayment)
        val failure = OutgoingPaymentPacket.buildWillAddHtlcFailure(paymentHandler.nodeParams.nodePrivateKey, willAddHtlc, IncorrectOrUnknownPaymentDetails(defaultAmount, TestConstants.defaultBlockHeight.toLong()))
        assertIs<WillFailHtlc>(failure)
        assertEquals(listOf(SendOnTheFlyFundingMessage(failure)), result.actions)
    }

    @Test
    fun `receive trampoline will_add_htlc with an incorrect payment secret`() = runSuspendTest {
        val (paymentHandler, incomingPayment, _) = createFixture(defaultAmount)
        checkDbPayment(incomingPayment, paymentHandler.db)
        val willAddHtlc = run {
            // We simulate a trampoline-relay with a dummy channel hop between the liquidity provider and the wallet.
            val (amount, expiry, trampolineOnion) = OutgoingPaymentPacket.buildPacket(
                incomingPayment.paymentHash,
                listOf(NodeHop(TestConstants.Alice.nodeParams.nodeId, TestConstants.Bob.nodeParams.nodeId, CltvExpiryDelta(144), 0.msat)),
                makeMppPayload(defaultAmount, defaultAmount, randomBytes32()),
                null
            )
            assertTrue(trampolineOnion.packet.payload.size() < 500)
            makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, PaymentOnion.FinalPayload.Standard.createTrampolinePayload(amount, amount, expiry, randomBytes32(), trampolineOnion.packet))
        }
        val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        assertEquals(incomingPayment, result.incomingPayment)
        val failure = OutgoingPaymentPacket.buildWillAddHtlcFailure(paymentHandler.nodeParams.nodePrivateKey, willAddHtlc, IncorrectOrUnknownPaymentDetails(defaultAmount, TestConstants.defaultBlockHeight.toLong()))
        assertIs<WillFailHtlc>(failure)
        assertEquals(listOf(SendOnTheFlyFundingMessage(failure)), result.actions)
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun `receive will_add_htlc with a fee too high`() = runSuspendTest {
        val fundingRates = LiquidityAds.WillFundRates(
            // Note that we use a fixed liquidity fees to make testing easier.
            fundingRates = listOf(LiquidityAds.FundingLease.Basic(0.sat, 250_000.sat, LiquidityAds.LeaseRate(0, 5_000.sat, 0))),
            paymentTypes = setOf(LiquidityAds.PaymentType.FromChannelBalance, LiquidityAds.PaymentType.FromFutureHtlc),
        )
        val inboundLiquidityTarget = 100_000.sat
        assertEquals(5_000.sat, fundingRates.fundingRates.first().fees(TestConstants.feeratePerKw, inboundLiquidityTarget, inboundLiquidityTarget).total)
        val defaultPolicy = LiquidityPolicy.Auto(inboundLiquidityTarget, maxAbsoluteFee = 5_000.sat, maxRelativeFeeBasisPoints = 500, skipAbsoluteFeeCheck = false)
        val testCases = listOf(
            // If payment amount is at least twice the fees, we accept the payment.
            Triple(defaultPolicy, 10_000_000.msat, null),
            // If payment is too close to the fee, we reject the payment.
            Triple(defaultPolicy, 9_999_999.msat, LiquidityEvents.Rejected.Reason.MissingOffChainAmountTooLow(9_999_999.msat)),
            // If our peer doesn't offer a funding lease for the payment amount, we reject the payment.
            Triple(defaultPolicy, 200_000_000.msat, LiquidityEvents.Rejected.Reason.NoMatchingFundingRate),
            // If fee is above our liquidity policy maximum fee, we reject the payment.
            Triple(defaultPolicy.copy(maxAbsoluteFee = 4999.sat), 10_000_000.msat, LiquidityEvents.Rejected.Reason.TooExpensive.OverAbsoluteFee(4999.sat)),
            // If fee is above our liquidity policy relative fee, we reject the payment.
            Triple(defaultPolicy.copy(maxRelativeFeeBasisPoints = 249), 100_000_000.msat, LiquidityEvents.Rejected.Reason.TooExpensive.OverRelativeFee(249)),
            // If we disabled automatic liquidity management, we reject the payment.
            Triple(LiquidityPolicy.Disable, 10_000_000.msat, LiquidityEvents.Rejected.Reason.PolicySetToDisabled),
        )
        testCases.forEach { (policy, paymentAmount, failure) ->
            val (paymentHandler, incomingPayment, paymentSecret) = createFixture(paymentAmount, fundingRates)
            paymentHandler.nodeParams.liquidityPolicy.emit(policy)
            paymentHandler.nodeParams._nodeEvents.resetReplayCache()
            val add = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(paymentAmount, paymentAmount, paymentSecret))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            when (failure) {
                null -> {
                    assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
                    assertEquals(incomingPayment, result.incomingPayment)
                    assertTrue(result.actions.filterIsInstance<OpenOrSplicePayment>().isNotEmpty())
                }
                else -> {
                    assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
                    val expected = OutgoingPaymentPacket.buildWillAddHtlcFailure(paymentHandler.nodeParams.nodePrivateKey, add, TemporaryNodeFailure)
                    assertIs<WillFailHtlc>(expected)
                    assertEquals(listOf(SendOnTheFlyFundingMessage(expected)), result.actions)
                    val event = paymentHandler.nodeParams.nodeEvents.first()
                    assertIs<LiquidityEvents.Rejected>(event)
                    assertEquals(event.reason, failure)
                }
            }
        }
    }

    @Test
    fun `receive multipart payment with a mix of HTLC and will_add_htlc`() = runSuspendTest {
        val channelId = randomBytes32()
        val (amount1, amount2) = listOf(50_000_000.msat, 60_000_000.msat)
        val totalAmount = amount1 + amount2
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(totalAmount)
        checkDbPayment(incomingPayment, paymentHandler.db)

        // Step 1 of 2:
        //  - Alice sends a normal HTLC to Bob first
        //  - Bob doesn't accept the MPP set yet
        run {
            val htlc = makeUpdateAddHtlc(0, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(htlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 3:
        //  - Alice sends will_add_htlc to Bob
        //  - Bob triggers an open/splice
        run {
            val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret))
            val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertEquals(1, result.actions.size)
            val openOrSplice = result.actions.first() as OpenOrSplicePayment
            assertEquals(incomingPayment.preimage, openOrSplice.preimage)
            assertEquals(amount2.truncateToSatoshi() + LiquidityPolicy.minInboundLiquidityTarget, openOrSplice.requestedAmount)
            assertEquals(totalAmount, openOrSplice.paymentAmount)
            assertNull(paymentHandler.db.getIncomingPayment(incomingPayment.paymentHash)?.received)
        }

        // Step 3 of 3:
        //  - After the splice completes, Alice sends a second HTLC to Bob
        //  - Bob accepts the MPP set
        run {
            val htlc = makeUpdateAddHtlc(1, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret))
            val result = paymentHandler.process(htlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
            val (expectedActions, expectedReceivedWith) = setOf(
                // @formatter:off
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(0, incomingPayment.preimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount1, channelId, 0, fundingFee = null),
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(1, incomingPayment.preimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount2, channelId, 1, fundingFee = null),
                // @formatter:on
            ).unzip()
            assertEquals(expectedActions.toSet(), result.actions.toSet())
            assertEquals(totalAmount, result.received.amount)
            assertEquals(expectedReceivedWith, result.received.receivedWith)
            checkDbPayment(result.incomingPayment, paymentHandler.db)
        }
    }

    @Test
    fun `receive multipart payment with a mix of HTLC and will_add_htlc -- fee too high`() = runSuspendTest {
        val channelId = randomBytes32()
        val (amount1, amount2) = listOf(50_000_000.msat, 50_000_000.msat)
        val totalAmount = amount1 + amount2
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(totalAmount)
        checkDbPayment(incomingPayment, paymentHandler.db)

        // Step 1 of 2:
        //  - Alice sends a normal HTLC to Bob first
        //  - Bob doesn't accept the MPP set yet
        run {
            val htlc = makeUpdateAddHtlc(0, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(htlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 4:
        //  - Alice sends will_add_htlc to Bob
        //  - Bob fails everything because the funding fee is too high
        run {
            val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret))
            paymentHandler.nodeParams.liquidityPolicy.emit(LiquidityPolicy.Auto(null, 100.sat, 100, skipAbsoluteFeeCheck = false))
            val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
            assertEquals(2, result.actions.size)
            val willFailHtlc = result.actions.filterIsInstance<SendOnTheFlyFundingMessage>().firstOrNull()?.message
            assertIs<WillFailHtlc>(willFailHtlc).also { assertEquals(willAddHtlc.id, it.id) }
            val failHtlc = ChannelCommand.Htlc.Settlement.Fail(0, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(TemporaryNodeFailure), commit = true)
            assertTrue(result.actions.contains(WrappedChannelCommand(channelId, failHtlc)))
            assertNull(paymentHandler.db.getIncomingPayment(incomingPayment.paymentHash)?.received)
        }

        // Step 3 of 4:
        //  - Alice sends the first HTLC to Bob again
        //  - Bob doesn't accept the MPP set yet
        run {
            val htlc = makeUpdateAddHtlc(1, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(htlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 4 of 4:
        //  - Alice sends the second HTLC to Bob
        //  - Bob accepts the MPP payment
        run {
            val htlc = makeUpdateAddHtlc(2, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret))
            val result = paymentHandler.process(htlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
            val (expectedActions, expectedReceivedWith) = setOf(
                // @formatter:off
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(1, incomingPayment.preimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount1, channelId, 1, fundingFee = null),
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(2, incomingPayment.preimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount2, channelId, 2, fundingFee = null),
                // @formatter:on
            ).unzip()
            assertEquals(expectedActions.toSet(), result.actions.toSet())
            assertEquals(totalAmount, result.received.amount)
            assertEquals(expectedReceivedWith, result.received.receivedWith)
            checkDbPayment(result.incomingPayment, paymentHandler.db)
        }
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun `receive will_add_htlc added to fee credit`() = runSuspendTest {
        val policy = LiquidityPolicy.Auto(inboundLiquidityTarget = 100_000.sat, maxAbsoluteFee = 500.sat, maxRelativeFeeBasisPoints = 1000, skipAbsoluteFeeCheck = false)
        val totalAmount = 2500.msat
        val testCases = listOf(
            // We don't have any fee credit: we add the payment to our credit regardless of liquidity fees.
            0.msat to null,
            // We have enough fee credit for an on-chain operation, but the fees are too high for our policy.
            20_000_000.msat to LiquidityEvents.Rejected.Reason.TooExpensive.OverAbsoluteFee(500.sat)
        )
        testCases.forEach { (currentFeeCredit, failure) ->
            val (paymentHandler, incomingPayment, paymentSecret) = createFeeCreditFixture(totalAmount, policy)
            paymentHandler.nodeParams._nodeEvents.resetReplayCache()
            val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(totalAmount, totalAmount, paymentSecret))
            val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw, currentFeeCredit)
            when (failure) {
                null -> {
                    assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
                    assertEquals(listOf(SendOnTheFlyFundingMessage(AddFeeCredit(paymentHandler.nodeParams.chainHash, incomingPayment.preimage))), result.actions)
                    assertEquals(totalAmount, result.received.amount)
                    assertEquals(listOf(IncomingPayment.ReceivedWith.AddedToFeeCredit(totalAmount)), result.received.receivedWith)
                    checkDbPayment(result.incomingPayment, paymentHandler.db)
                }
                else -> {
                    assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
                    assertEquals(1, result.actions.size)
                    val willFailHtlc = result.actions.filterIsInstance<SendOnTheFlyFundingMessage>().firstOrNull()?.message
                    assertIs<WillFailHtlc>(willFailHtlc)
                    assertEquals(willAddHtlc.id, willFailHtlc.id)
                    val event = paymentHandler.nodeParams.nodeEvents.first()
                    assertIs<LiquidityEvents.Rejected>(event)
                    assertEquals(event.reason, failure)
                }
            }
        }
    }

    @Test
    fun `receive multipart payment with a mix of HTLC and will_add_htlc added to fee credit`() = runSuspendTest {
        val channelId = randomBytes32()
        val (amount1, amount2) = listOf(10_000.msat, 5_000.msat)
        val totalAmount = amount1 + amount2
        val (paymentHandler, incomingPayment, paymentSecret) = createFeeCreditFixture(totalAmount, LiquidityPolicy.Auto(null, 50.sat, 100, skipAbsoluteFeeCheck = false))

        // Step 1 of 2:
        //  - Alice sends a normal HTLC to Bob first
        //  - Bob doesn't accept the MPP set yet
        run {
            val htlc = makeUpdateAddHtlc(0, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(htlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw, currentFeeCredit = 0.msat)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 2:
        //  - Alice sends will_add_htlc to Bob
        //  - Bob adds it to its fee credit and fulfills the HTLC
        run {
            val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret))
            val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw, currentFeeCredit = 0.msat)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
            val (expectedActions, expectedReceivedWith) = setOf(
                // @formatter:off
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(0, incomingPayment.preimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount1, channelId, 0, fundingFee = null),
                SendOnTheFlyFundingMessage(AddFeeCredit(paymentHandler.nodeParams.chainHash, incomingPayment.preimage)) to IncomingPayment.ReceivedWith.AddedToFeeCredit(amount2),
                // @formatter:on
            ).unzip()
            assertEquals(expectedActions.toSet(), result.actions.toSet())
            assertEquals(totalAmount, result.received.amount)
            assertEquals(expectedReceivedWith, result.received.receivedWith)
            checkDbPayment(result.incomingPayment, paymentHandler.db)
        }
    }

    @Test
    fun `receive will_add_htlc with enough fee credit`() = runSuspendTest {
        // This tiny HTLC wouldn't be accepted if we didn't have enough fee credit.
        val totalAmount = 500.msat
        val currentFeeCredit = 20_000_000.msat
        val (paymentHandler, incomingPayment, paymentSecret) = createFeeCreditFixture(totalAmount, LiquidityPolicy.Auto(100_000.sat, 5000.sat, 1000, skipAbsoluteFeeCheck = false))
        val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(totalAmount, totalAmount, paymentSecret))
        val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw, currentFeeCredit)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
        assertEquals(1, result.actions.size)
        val openOrSplice = result.actions.first()
        assertIs<OpenOrSplicePayment>(openOrSplice)
        assertEquals(totalAmount, openOrSplice.paymentAmount)
        assertEquals(100_000.sat, openOrSplice.requestedAmount)
        // We don't update the payments DB: we're waiting to receive HTLCs after the open/splice.
        assertNull(paymentHandler.db.getIncomingPayment(incomingPayment.paymentHash)?.received)
    }

    @Test
    fun `receive will_add_htlc larger than fee credit threshold`() = runSuspendTest {
        // Large payments shouldn't be added to fee credit.
        val totalAmount = 20_000_000.msat
        val (paymentHandler, incomingPayment, paymentSecret) = createFeeCreditFixture(totalAmount, LiquidityPolicy.Auto(100_000.sat, 5000.sat, 1000, skipAbsoluteFeeCheck = false))
        val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(totalAmount, totalAmount, paymentSecret))
        val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw, currentFeeCredit = 100.msat)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
        assertEquals(1, result.actions.size)
        val openOrSplice = result.actions.first()
        assertIs<OpenOrSplicePayment>(openOrSplice)
        assertEquals(totalAmount, openOrSplice.paymentAmount)
        assertEquals(120_000.sat, openOrSplice.requestedAmount)
        // We don't update the payments DB: we're waiting to receive HTLCs after the open/splice.
        assertNull(paymentHandler.db.getIncomingPayment(incomingPayment.paymentHash)?.received)
    }

    @Test
    fun `receive multipart payment with funding fee`() = runSuspendTest {
        val channelId = randomBytes32()
        val (amount1, amount2) = listOf(50_000_000.msat, 60_000_000.msat)
        val totalAmount = amount1 + amount2
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(totalAmount)
        checkDbPayment(incomingPayment, paymentHandler.db)

        // Step 1 of 2:
        //  - Alice sends a normal HTLC to Bob first
        //  - Bob doesn't accept the MPP set yet
        run {
            val htlc = makeUpdateAddHtlc(0, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(htlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 3:
        //  - Alice sends will_add_htlc to Bob
        //  - Bob triggers an open/splice
        val purchase = run {
            val willAddHtlc = makeWillAddHtlc(paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret))
            val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertEquals(1, result.actions.size)
            val splice = result.actions.first() as OpenOrSplicePayment
            // The splice transaction is successfully signed and stored in the DB.
            val lease = LiquidityAds.Lease(
                splice.requestedAmount,
                splice.leaseFees(TestConstants.feeratePerKw),
                LiquidityAds.PaymentDetails.FromFutureHtlc(listOf(incomingPayment.paymentHash)),
                randomBytes64(),
                LiquidityAds.FundingLeaseWitness.Basic(randomBytes(33).byteVector())
            )
            val purchase = InboundLiquidityOutgoingPayment(UUID.randomUUID(), channelId, TxId(randomBytes32()), 500.sat, lease, 0, null, null)
            paymentHandler.db.addOutgoingPayment(purchase)
            purchase
        }

        // Step 3 of 3:
        //  - After the splice completes, Alice sends a second HTLC to Bob with the funding fee deduced
        //  - Bob accepts the MPP set
        run {
            val htlc = makeUpdateAddHtlc(1, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret), fundingFee = purchase.fundingFee)
            assertTrue(htlc.amountMsat < amount2)
            val result = paymentHandler.process(htlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
            val (expectedActions, expectedReceivedWith) = setOf(
                // @formatter:off
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(0, incomingPayment.preimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount1, channelId, 0, fundingFee = null),
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(1, incomingPayment.preimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount2 - purchase.fundingFee.amount, channelId, 1, purchase.fundingFee),
                // @formatter:on
            ).unzip()
            assertEquals(expectedActions.toSet(), result.actions.toSet())
            assertEquals(totalAmount - purchase.fundingFee.amount, result.received.amount)
            assertEquals(expectedReceivedWith, result.received.receivedWith)
            checkDbPayment(result.incomingPayment, paymentHandler.db)
        }
    }

    @Test
    fun `receive payment with funding fee -- unknown transaction`() = runSuspendTest {
        val channelId = randomBytes32()
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(defaultAmount)
        checkDbPayment(incomingPayment, paymentHandler.db)

        val fundingFee = LiquidityAds.FundingFee(3_000_000.msat, TxId(randomBytes32()))
        val add = makeUpdateAddHtlc(0, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount, defaultAmount, paymentSecret), fundingFee = fundingFee)
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        val expected = ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(defaultAmount, TestConstants.defaultBlockHeight.toLong())), commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
    }

    @Test
    fun `receive payment with funding fee -- fee too high`() = runSuspendTest {
        val channelId = randomBytes32()
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(defaultAmount)
        checkDbPayment(incomingPayment, paymentHandler.db)

        // We have a matching transaction in our DB.
        val lease = LiquidityAds.Lease(
            defaultAmount.truncateToSatoshi() + LiquidityPolicy.minInboundLiquidityTarget,
            LiquidityAds.LeaseFees(2000.sat, 3000.sat),
            LiquidityAds.PaymentDetails.FromFutureHtlc(listOf(incomingPayment.paymentHash)),
            randomBytes64(),
            LiquidityAds.FundingLeaseWitness.Basic(randomBytes(33).byteVector())
        )
        val purchase = InboundLiquidityOutgoingPayment(UUID.randomUUID(), channelId, TxId(randomBytes32()), 500.sat, lease, 0, null, null)
        paymentHandler.db.addOutgoingPayment(purchase)

        run {
            // If the funding fee is higher than what was agreed upon, we reject the payment.
            val fundingFeeTooHigh = purchase.fundingFee.copy(amount = purchase.fundingFee.amount + 1.msat)
            val add = makeUpdateAddHtlc(0, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount, defaultAmount, paymentSecret), fundingFee = fundingFeeTooHigh)
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
            val expected = ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(defaultAmount, TestConstants.defaultBlockHeight.toLong())), commit = true)
            assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
        }
        run {
            // If our peer retries with the right funding fee, we accept it.
            val add = makeUpdateAddHtlc(1, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount, defaultAmount, paymentSecret), fundingFee = purchase.fundingFee)
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
            assertEquals(listOf(WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(1, incomingPayment.preimage, commit = true))), result.actions)
            assertEquals(defaultAmount - purchase.fundingFee.amount, result.received.amount)
            assertEquals(listOf(IncomingPayment.ReceivedWith.LightningPayment(defaultAmount - purchase.fundingFee.amount, channelId, 1, purchase.fundingFee)), result.received.receivedWith)
            checkDbPayment(result.incomingPayment, paymentHandler.db)
        }
    }

    @Test
    fun `receive payment with funding fee -- invalid payment type`() = runSuspendTest {
        val channelId = randomBytes32()
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(defaultAmount)
        checkDbPayment(incomingPayment, paymentHandler.db)

        // We have a matching transaction in our DB, but we paid the fees from our channel balance already.
        val lease = LiquidityAds.Lease(
            defaultAmount.truncateToSatoshi() + LiquidityPolicy.minInboundLiquidityTarget,
            LiquidityAds.LeaseFees(2000.sat, 3000.sat),
            LiquidityAds.PaymentDetails.FromChannelBalance,
            randomBytes64(),
            LiquidityAds.FundingLeaseWitness.Basic(randomBytes(33).byteVector())
        )
        val purchase = InboundLiquidityOutgoingPayment(UUID.randomUUID(), channelId, TxId(randomBytes32()), 500.sat, lease, 0, null, null)
        paymentHandler.db.addOutgoingPayment(purchase)

        val add = makeUpdateAddHtlc(0, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount, defaultAmount, paymentSecret), fundingFee = purchase.fundingFee)
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        val expected = ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(defaultAmount, TestConstants.defaultBlockHeight.toLong())), commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
    }

    @Test
    fun `receive payment with funding fee -- invalid payment_hash`() = runSuspendTest {
        val channelId = randomBytes32()
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(defaultAmount)
        checkDbPayment(incomingPayment, paymentHandler.db)

        // We have a matching transaction in our DB, but the fees must be paid with a different payment_hash.
        val lease = LiquidityAds.Lease(
            defaultAmount.truncateToSatoshi() + LiquidityPolicy.minInboundLiquidityTarget,
            LiquidityAds.LeaseFees(2000.sat, 3000.sat),
            LiquidityAds.PaymentDetails.FromFutureHtlc(listOf(randomBytes32())),
            randomBytes64(),
            LiquidityAds.FundingLeaseWitness.Basic(randomBytes(33).byteVector())
        )
        val purchase = InboundLiquidityOutgoingPayment(UUID.randomUUID(), channelId, TxId(randomBytes32()), 500.sat, lease, 0, null, null)
        paymentHandler.db.addOutgoingPayment(purchase)

        val add = makeUpdateAddHtlc(0, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount, defaultAmount, paymentSecret), fundingFee = purchase.fundingFee)
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        val expected = ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(defaultAmount, TestConstants.defaultBlockHeight.toLong())), commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
    }

    @Test
    fun `receive multipart payment with amount-less invoice`() = runSuspendTest {
        val channelId = randomBytes32()
        val (amount1, amount2) = Pair(100_000.msat, 50_000.msat)
        val totalAmount = amount1 + amount2
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(invoiceAmount = null)

        // Step 1 of 2:
        // - Alice sends first multipart htlc to Bob
        // - Bob doesn't accept the MPP set yet
        run {
            val add = makeUpdateAddHtlc(7, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 2:
        // - Alice sends second multipart htlc to Bob
        // - Bob now accepts the MPP set
        run {
            val add = makeUpdateAddHtlc(11, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
            val expected = setOf(
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(7, incomingPayment.preimage, commit = true)),
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(11, incomingPayment.preimage, commit = true)),
            )
            assertEquals(expected, result.actions.toSet())
        }
    }

    @Test
    fun `receive multipart payment with amount greater than total amount`() = runSuspendTest {
        val channelId = randomBytes32()
        val requestedAmount = 180_000.msat
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(requestedAmount)
        // The sender overpays at many different layers:
        //  - the invoice requests a payment of 180 000 msat
        //  - the sender announces a total amount of 190 000 msat
        //  - the sum of individual HTLC's onion amounts is 200 000 msat
        //  - the sum of individual HTLC's amounts is 205 000 msat
        val totalAmount = 190_000.msat
        val add1 = makeUpdateAddHtlc(3, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(100_000.msat, totalAmount, paymentSecret))
        val add2 = makeUpdateAddHtlc(5, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(60_000.msat, totalAmount, paymentSecret)).copy(amountMsat = 65_000.msat)
        val add3 = makeUpdateAddHtlc(6, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(40_000.msat, totalAmount, paymentSecret))

        // Step 1 of 2:
        // - Alice sends first 2 multipart htlcs to Bob.
        // - Bob doesn't accept the MPP set yet
        listOf(add1, add2).forEach { add ->
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 2:
        // - Alice sends third multipart htlc to Bob
        // - Bob now accepts the MPP set
        run {
            val result = paymentHandler.process(add3, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
            val expected = setOf(
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(3, incomingPayment.preimage, commit = true)),
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(5, incomingPayment.preimage, commit = true)),
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(6, incomingPayment.preimage, commit = true))
            )
            assertEquals(expected, result.actions.toSet())
        }
    }

    @Test
    fun `receive multipart payment with greater expiry`() = runSuspendTest {
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(defaultAmount)
        val add = makeUpdateAddHtlc(0, randomBytes32(), paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount, defaultAmount, paymentSecret))
        val addGreaterExpiry = add.copy(cltvExpiry = add.cltvExpiry + CltvExpiryDelta(6))
        val result = paymentHandler.process(addGreaterExpiry, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
        val expected = WrappedChannelCommand(add.channelId, ChannelCommand.Htlc.Settlement.Fulfill(add.id, incomingPayment.preimage, commit = true))
        assertEquals(setOf(expected), result.actions.toSet())
    }

    @Test
    fun `reprocess duplicate htlcs`() = runSuspendTest {
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(defaultAmount)

        // We receive a first multipart htlc.
        val add1 = makeUpdateAddHtlc(3, randomBytes32(), paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount / 2, defaultAmount, paymentSecret))
        val result1 = paymentHandler.process(add1, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result1)
        assertTrue(result1.actions.isEmpty())

        // This htlc is reprocessed (e.g. because the wallet restarted).
        val result1b = paymentHandler.process(add1, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result1b)
        assertTrue(result1b.actions.isEmpty())

        // We receive the second multipart htlc.
        val add2 = makeUpdateAddHtlc(5, randomBytes32(), paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount / 2, defaultAmount, paymentSecret))
        val result2 = paymentHandler.process(add2, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result2)
        assertEquals(defaultAmount, result2.received.amount)
        val expected = setOf(
            WrappedChannelCommand(add1.channelId, ChannelCommand.Htlc.Settlement.Fulfill(add1.id, incomingPayment.preimage, commit = true)),
            WrappedChannelCommand(add2.channelId, ChannelCommand.Htlc.Settlement.Fulfill(add2.id, incomingPayment.preimage, commit = true))
        )
        assertEquals(expected, result2.actions.toSet())

        // The second htlc is reprocessed (e.g. because our peer disconnected before we could send them the preimage).
        val result2b = paymentHandler.process(add2, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result2b)
        assertEquals(defaultAmount, result2b.received.amount)
        assertEquals(listOf(WrappedChannelCommand(add2.channelId, ChannelCommand.Htlc.Settlement.Fulfill(add2.id, incomingPayment.preimage, commit = true))), result2b.actions)
    }

    @Test
    fun `reprocess failed htlcs`() = runSuspendTest {
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(defaultAmount)

        // We receive a first multipart htlc.
        val add = makeUpdateAddHtlc(1, randomBytes32(), paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount / 2, defaultAmount, paymentSecret))
        val result1 = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result1)
        assertTrue(result1.actions.isEmpty())

        // It expires after a while.
        val actions1 = paymentHandler.checkPaymentsTimeout(currentTimestampSeconds() + paymentHandler.nodeParams.mppAggregationWindow.inWholeSeconds + 2)
        val addTimeout = ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(PaymentTimeout), commit = true)
        assertEquals(listOf(WrappedChannelCommand(add.channelId, addTimeout)), actions1)

        // For some reason, the channel was offline, didn't process the failure and retransmits the htlc.
        val result2 = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result2)
        assertTrue(result2.actions.isEmpty())

        // It expires again.
        val actions2 = paymentHandler.checkPaymentsTimeout(currentTimestampSeconds() + paymentHandler.nodeParams.mppAggregationWindow.inWholeSeconds + 2)
        assertEquals(listOf(WrappedChannelCommand(add.channelId, addTimeout)), actions2)

        // The channel was offline again, didn't process the failure and retransmits the htlc, but it is now close to its expiry.
        val currentBlockHeight = add.cltvExpiry.toLong().toInt() - 3
        val result3 = paymentHandler.process(add, currentBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result3)
        val addExpired = ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(defaultAmount, currentBlockHeight.toLong())), commit = true)
        assertEquals(listOf(WrappedChannelCommand(add.channelId, addExpired)), result3.actions)
    }

    @Test
    fun `invoice expired`() = runSuspendTest {
        val paymentHandler = IncomingPaymentHandler(TestConstants.Bob.nodeParams, InMemoryPaymentsDb(), TestConstants.fundingRates)
        val (incomingPayment, paymentSecret) = makeIncomingPayment(
            payee = paymentHandler,
            amount = defaultAmount,
            timestamp = currentTimestampSeconds() - 3600 - 60, // over one hour ago
            expirySeconds = 3600 // one hour expiration
        )
        val add = makeUpdateAddHtlc(0, randomBytes32(), paymentHandler, incomingPayment.paymentHash, makeMppPayload(10_000.msat, defaultAmount, paymentSecret))
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)

        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        val expected = ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(defaultAmount, TestConstants.defaultBlockHeight.toLong())), commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
    }

    @Test
    fun `invoice unknown`() = runSuspendTest {
        val (paymentHandler, _, _) = createFixture(defaultAmount)
        val add = makeUpdateAddHtlc(0, randomBytes32(), paymentHandler, randomBytes32(), makeMppPayload(defaultAmount, defaultAmount, randomBytes32()))
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)

        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        val expected = ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(defaultAmount, TestConstants.defaultBlockHeight.toLong())), commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
    }

    @Test
    fun `invalid onion`() = runSuspendTest {
        val (paymentHandler, incomingPayment, _) = createFixture(defaultAmount)
        val cltvExpiry = CltvExpiryDelta(144).toCltvExpiry(TestConstants.defaultBlockHeight.toLong())
        val badOnion = OnionRoutingPacket(0, ByteVector("0x02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"), randomBytes(OnionRoutingPacket.PaymentPacketLength).toByteVector(), randomBytes32())
        val add = UpdateAddHtlc(randomBytes32(), 0, defaultAmount, incomingPayment.paymentHash, cltvExpiry, badOnion)
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)

        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        // The current flow of error checking within the codebase would be:
        // 1. InvalidOnionKey
        // 2. InvalidOnionHmac
        // Since we used a valid pubKey, we should get an hmac failure.
        val expectedErr = InvalidOnionHmac(hash(badOnion))
        val expected = ChannelCommand.Htlc.Settlement.FailMalformed(add.id, expectedErr.onionHash, expectedErr.code, commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
    }

    @Test
    fun `invalid cltv expiry`() = runSuspendTest {
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(defaultAmount)
        val lowExpiry = CltvExpiryDelta(2)
        val add = makeUpdateAddHtlc(0, randomBytes32(), paymentHandler, incomingPayment.paymentHash, makeMppPayload(defaultAmount / 2, defaultAmount, paymentSecret, lowExpiry))
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)

        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        val expected = ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(defaultAmount, TestConstants.defaultBlockHeight.toLong())), commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
    }

    @Test
    fun `amount too low or too high`() = runSuspendTest {
        val requestedAmount = 30_000.msat
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(requestedAmount)

        val payloads = listOf(
            makeMppPayload(requestedAmount / 3, requestedAmount / 3, paymentSecret), // too low
            makeMppPayload(requestedAmount * 3, requestedAmount * 3, paymentSecret) // too high
        )
        payloads.forEach { payload ->
            val add = makeUpdateAddHtlc(3, randomBytes32(), paymentHandler, incomingPayment.paymentHash, payload)
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
            val expected = ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(payload.totalAmount, TestConstants.defaultBlockHeight.toLong())), commit = true)
            assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
        }
    }

    @Test
    fun `multipart total_amount mismatch`() = runSuspendTest {
        val channelId = randomBytes32()
        val (amount1, amount2, amount3) = listOf(25_000.msat, 40_000.msat, 30_000.msat)
        val totalAmount = amount1 + amount2 + amount3
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(totalAmount)

        // Step 1 of 2:
        // - Alice sends first multipart htlc to Bob
        // - Bob doesn't accept the MPP set yet
        run {
            val add = makeUpdateAddHtlc(1, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 2:
        // - Alice sends second multipart htlc to Bob.
        // - Bob detects some shenanigans
        // - Bob rejects the entire MPP set
        run {
            val payload = makeMppPayload(amount2, totalAmount + MilliSatoshi(1), paymentSecret)
            val add = makeUpdateAddHtlc(2, channelId, paymentHandler, incomingPayment.paymentHash, payload)
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
            val expected = setOf(
                WrappedChannelCommand(
                    channelId,
                    ChannelCommand.Htlc.Settlement.Fail(1, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(totalAmount, TestConstants.defaultBlockHeight.toLong())), commit = true)
                ),
                WrappedChannelCommand(
                    channelId,
                    ChannelCommand.Htlc.Settlement.Fail(2, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(totalAmount + 1.msat, TestConstants.defaultBlockHeight.toLong())), commit = true)
                ),
            )
            assertEquals(expected, result.actions.toSet())
        }
    }

    @Test
    fun `invalid payment secret`() = runSuspendTest {
        val (amount1, amount2) = listOf(50_000.msat, 45_000.msat)
        val totalAmount = amount1 + amount2
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(totalAmount)

        // Step 1 of 2:
        // - Alice sends first multipart htlc to Bob
        // - Bob doesn't accept the MPP set yet
        run {
            val add = makeUpdateAddHtlc(1, randomBytes32(), paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 2:
        // - Someone sends an htlc with a different payment secret
        // - Bob rejects only that htlc, not Alice's valid one
        run {
            val payload = makeMppPayload(amount2, totalAmount, randomBytes32()) // <--- invalid payment secret
            val add = makeUpdateAddHtlc(1, randomBytes32(), paymentHandler, incomingPayment.paymentHash, payload)
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
            val expected = ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(totalAmount, TestConstants.defaultBlockHeight.toLong())), commit = true)
            assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
        }
    }

    @Test
    fun `mpp timeout`() = runSuspendTest {
        val startTime = currentTimestampSeconds()
        val channelId = randomBytes32()
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(defaultAmount)

        // Step 1 of 3:
        // - Alice sends (unfinished) multipart htlcs to Bob.
        run {
            listOf(1L, 2L).forEach { id ->
                val add = makeUpdateAddHtlc(id, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(10_000.msat, defaultAmount, paymentSecret))
                val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
                assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
                assertTrue(result.actions.isEmpty())
            }
        }

        // Step 2 of 3:
        // - don't expire the multipart htlcs too soon.
        run {
            val currentTimestampSeconds = startTime + paymentHandler.nodeParams.mppAggregationWindow.inWholeSeconds - 2
            val actions = paymentHandler.checkPaymentsTimeout(currentTimestampSeconds)
            assertTrue(actions.isEmpty())
        }

        // Step 3 of 3:
        // - expire the htlc-set after configured expiration.
        run {
            val currentTimestampSeconds = startTime + paymentHandler.nodeParams.mppAggregationWindow.inWholeSeconds + 2
            val actions = paymentHandler.checkPaymentsTimeout(currentTimestampSeconds)
            val expected = setOf(
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fail(1, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(PaymentTimeout), commit = true)),
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fail(2, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(PaymentTimeout), commit = true)),
            )
            assertEquals(expected, actions.toSet())
        }
    }

    @Test
    fun `mpp timeout then success`() = runSuspendTest {
        val startTime = currentTimestampSeconds()
        val channelId = randomBytes32()
        val (amount1, amount2) = listOf(60_000.msat, 30_000.msat)
        val totalAmount = amount1 + amount2
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(totalAmount)

        // Step 1 of 4:
        // - Alice sends single (unfinished) multipart htlc to Bob.
        run {
            val add = makeUpdateAddHtlc(1, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 4:
        // - the MPP set times out
        run {
            val currentTimestampSeconds = startTime + paymentHandler.nodeParams.mppAggregationWindow.inWholeSeconds + 2
            val actions = paymentHandler.checkPaymentsTimeout(currentTimestampSeconds)
            val expected = WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fail(1, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(PaymentTimeout), commit = true))
            assertEquals(setOf(expected), actions.toSet())
        }

        // Step 3 of 4:
        // - Alice tries again, and sends another single (unfinished) multipart htlc to Bob.
        run {
            val add = makeUpdateAddHtlc(3, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertTrue(result.actions.isEmpty())
        }

        // Step 4 of 4:
        // - Alice sends second and last part of mpp
        // - Bob accepts htlc set
        run {
            val add = makeUpdateAddHtlc(4, channelId, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
            val expected = setOf(
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(3, incomingPayment.preimage, commit = true)),
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(4, incomingPayment.preimage, commit = true)),
            )
            assertEquals(expected, result.actions.toSet())
        }
    }

    @Test
    fun `fulfill locally replayed htlcs`() = runSuspendTest {
        val (amount1, amount2) = listOf(12_000.msat, 50_000.msat)
        val (channelId1, channelId2) = listOf(randomBytes32(), randomBytes32())
        val totalAmount = amount1 + amount2
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(totalAmount)
        val (htlc1, htlc2) = listOf(
            makeUpdateAddHtlc(876, channelId1, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret)),
            makeUpdateAddHtlc(2, channelId2, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret)),
        )

        // Step 1 of 2:
        // - Alice receives complete mpp set
        run {
            val result1 = paymentHandler.process(htlc1, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result1)
            assertTrue(result1.actions.isEmpty())

            val result2 = paymentHandler.process(htlc2, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result2)

            val expected = setOf(
                WrappedChannelCommand(channelId1, ChannelCommand.Htlc.Settlement.Fulfill(htlc1.id, incomingPayment.preimage, commit = true)),
                WrappedChannelCommand(channelId2, ChannelCommand.Htlc.Settlement.Fulfill(htlc2.id, incomingPayment.preimage, commit = true)),
            )
            assertEquals(expected, result2.actions.toSet())
        }

        // Step 2 of 2:
        // - Alice receives local replay of htlc1 for the invoice she already completed. Must be fulfilled.
        run {
            val result = paymentHandler.process(htlc1, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
            val expected = WrappedChannelCommand(channelId1, ChannelCommand.Htlc.Settlement.Fulfill(htlc1.id, incomingPayment.preimage, commit = true))
            assertEquals(setOf(expected), result.actions.toSet())
        }
    }

    @Test
    fun `reject htlcs for already paid invoices`() = runSuspendTest {
        val (amount1, amount2) = listOf(60_000.msat, 30_000.msat)
        val (channelId1, channelId2) = listOf(randomBytes32(), randomBytes32())
        val totalAmount = amount1 + amount2
        val (paymentHandler, incomingPayment, paymentSecret) = createFixture(totalAmount)
        val (htlc1, htlc2) = listOf(
            makeUpdateAddHtlc(8, channelId1, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount1, totalAmount, paymentSecret)),
            makeUpdateAddHtlc(4, channelId2, paymentHandler, incomingPayment.paymentHash, makeMppPayload(amount2, totalAmount, paymentSecret)),
        )

        // Step 1 of 2:
        // - Alice receives complete mpp set
        run {
            val result1 = paymentHandler.process(htlc1, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result1)
            assertTrue(result1.actions.isEmpty())

            val result2 = paymentHandler.process(htlc2, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result2)

            val expected = setOf(
                WrappedChannelCommand(channelId1, ChannelCommand.Htlc.Settlement.Fulfill(htlc1.id, incomingPayment.preimage, commit = true)),
                WrappedChannelCommand(channelId2, ChannelCommand.Htlc.Settlement.Fulfill(htlc2.id, incomingPayment.preimage, commit = true)),
            )
            assertEquals(expected, result2.actions.toSet())
        }

        // Step 2 of 2:
        // - Alice receives an additional htlc (with new id) on channel1 for the invoice she already completed. Must be rejected.
        run {
            val add = htlc1.copy(id = 3)
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
            val expected = WrappedChannelCommand(
                channelId1, ChannelCommand.Htlc.Settlement.Fail(
                    3, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(
                        IncorrectOrUnknownPaymentDetails(totalAmount, TestConstants.defaultBlockHeight.toLong())
                    ), commit = true
                )
            )
            assertEquals(setOf(expected), result.actions.toSet())
        }

        // - Alice receives an htlc2 (but on a new channel) for the invoice she already completed. Must be rejected.
        run {
            val channelId3 = randomBytes32()
            val add = htlc2.copy(channelId = channelId3)
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
            val expected = WrappedChannelCommand(
                channelId3, ChannelCommand.Htlc.Settlement.Fail(
                    htlc2.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(
                        IncorrectOrUnknownPaymentDetails(totalAmount, TestConstants.defaultBlockHeight.toLong())
                    ), commit = true
                )
            )
            assertEquals(setOf(expected), result.actions.toSet())
        }
    }

    @Test
    fun `purge expired incoming payments`() = runSuspendTest {
        val paymentHandler = IncomingPaymentHandler(TestConstants.Bob.nodeParams, InMemoryPaymentsDb(), TestConstants.fundingRates)

        // create incoming payment that has expired and not been paid
        val expiredInvoice = paymentHandler.createInvoice(
            randomBytes32(), defaultAmount, Either.Left("expired"), listOf(), expirySeconds = 3600,
            timestampSeconds = 1
        )

        // create incoming payment that has expired and been paid
        delay(100.milliseconds)
        val paidInvoice = paymentHandler.createInvoice(
            defaultPreimage, defaultAmount, Either.Left("paid"), listOf(), expirySeconds = 3600,
            timestampSeconds = 100
        )
        paymentHandler.db.receivePayment(
            paidInvoice.paymentHash,
            receivedWith = listOf(
                IncomingPayment.ReceivedWith.NewChannel(
                    amount = 15_000_000.msat,
                    serviceFee = 1_000_000.msat,
                    miningFee = 0.sat,
                    channelId = randomBytes32(),
                    txId = TxId(randomBytes32()),
                    confirmedAt = null,
                    lockedAt = null
                )
            ),
            receivedAt = 101 // simulate incoming payment being paid before it expired
        )

        // create unexpired payment
        delay(100.milliseconds)
        val unexpiredInvoice = paymentHandler.createInvoice(randomBytes32(), defaultAmount, Either.Left("unexpired"), listOf(), expirySeconds = 3600)

        val unexpiredPayment = paymentHandler.db.getIncomingPayment(unexpiredInvoice.paymentHash)!!
        val paidPayment = paymentHandler.db.getIncomingPayment(paidInvoice.paymentHash)!!
        val expiredPayment = paymentHandler.db.getIncomingPayment(expiredInvoice.paymentHash)!!

        val db = paymentHandler.db
        assertIs<InMemoryPaymentsDb>(db)
        assertEquals(db.listIncomingPayments(5, 0), listOf(unexpiredPayment, paidPayment, expiredPayment))
        assertEquals(db.listExpiredPayments(), listOf(expiredPayment))
        assertEquals(paymentHandler.purgeExpiredPayments(), 1)
        assertEquals(db.listExpiredPayments(), emptyList())
        assertEquals(db.listIncomingPayments(5, 0), listOf(unexpiredPayment, paidPayment))
    }

    @Test
    fun `receive blinded payment with single HTLC`() = runSuspendTest {
        val paymentHandler = IncomingPaymentHandler(TestConstants.Bob.nodeParams, InMemoryPaymentsDb(), TestConstants.fundingRates)
        val preimage = randomBytes32()
        val paymentHash = Crypto.sha256(preimage).toByteVector32()
        val cltvExpiry = TestConstants.Bob.nodeParams.minFinalCltvExpiryDelta.toCltvExpiry(TestConstants.defaultBlockHeight.toLong())
        val (finalPayload, route) = makeBlindedPayload(TestConstants.Bob.nodeParams.nodeId, defaultAmount, defaultAmount, cltvExpiry, preimage = preimage)
        val add = makeUpdateAddHtlc(8, randomBytes32(), paymentHandler, paymentHash, finalPayload, route.blindingKey)
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)

        assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
        val expected = ChannelCommand.Htlc.Settlement.Fulfill(add.id, preimage, commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())

        assertEquals(result.incomingPayment.received, result.received)
        assertEquals(defaultAmount, result.received.amount)
        assertEquals(listOf(IncomingPayment.ReceivedWith.LightningPayment(defaultAmount, add.channelId, 8, null)), result.received.receivedWith)

        checkDbPayment(result.incomingPayment, paymentHandler.db)
    }

    @Test
    fun `receive blinded multipart payment with multiple HTLCs`() = runSuspendTest {
        val paymentHandler = IncomingPaymentHandler(TestConstants.Bob.nodeParams, InMemoryPaymentsDb(), TestConstants.fundingRates)
        val channelId = randomBytes32()
        val (amount1, amount2) = Pair(100_000.msat, 50_000.msat)
        val totalAmount = amount1 + amount2
        val preimage = randomBytes32()
        val paymentHash = Crypto.sha256(preimage).toByteVector32()
        val cltvExpiry = TestConstants.Bob.nodeParams.minFinalCltvExpiryDelta.toCltvExpiry(TestConstants.defaultBlockHeight.toLong())

        // Step 1 of 2:
        // - Alice sends first multipart htlc to Bob
        // - Bob doesn't accept the MPP set yet
        run {
            val (finalPayload, route) = makeBlindedPayload(TestConstants.Bob.nodeParams.nodeId, amount1, totalAmount, cltvExpiry, preimage = preimage)
            val add = makeUpdateAddHtlc(0, channelId, paymentHandler, paymentHash, finalPayload, route.blindingKey)
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertNull(result.incomingPayment.received)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 2:
        // - Alice sends second multipart htlc to Bob
        // - Bob now accepts the MPP set
        run {
            val (finalPayload, route) = makeBlindedPayload(TestConstants.Bob.nodeParams.nodeId, amount2, totalAmount, cltvExpiry, preimage = preimage)
            val add = makeUpdateAddHtlc(1, channelId, paymentHandler, paymentHash, finalPayload, route.blindingKey)
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
            val (expectedActions, expectedReceivedWith) = setOf(
                // @formatter:off
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(0, preimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount1, channelId, 0, null),
                WrappedChannelCommand(channelId, ChannelCommand.Htlc.Settlement.Fulfill(1, preimage, commit = true)) to IncomingPayment.ReceivedWith.LightningPayment(amount2, channelId, 1, null),
                // @formatter:on
            ).unzip()
            assertEquals(expectedActions.toSet(), result.actions.toSet())
            assertEquals(totalAmount, result.received.amount)
            assertEquals(expectedReceivedWith, result.received.receivedWith)
            checkDbPayment(result.incomingPayment, paymentHandler.db)
        }
    }

    @Test
    fun `receive blinded will_add_htlc`() = runSuspendTest {
        val (paymentHandler, _, _) = createFixture(defaultAmount)
        val preimage = randomBytes32()
        val paymentHash = Crypto.sha256(preimage).toByteVector32()
        val cltvExpiry = TestConstants.Bob.nodeParams.minFinalCltvExpiryDelta.toCltvExpiry(TestConstants.defaultBlockHeight.toLong())
        val (finalPayload, route) = makeBlindedPayload(TestConstants.Bob.nodeParams.nodeId, defaultAmount, defaultAmount, cltvExpiry, preimage = preimage)
        val willAddHtlc = makeWillAddHtlc(paymentHandler, paymentHash, finalPayload, route.blindingKey)
        val result = paymentHandler.process(willAddHtlc, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
        assertEquals(1, result.actions.size)
        val openOrSplice = result.actions.first()
        assertIs<OpenOrSplicePayment>(openOrSplice)
        assertEquals(preimage, openOrSplice.preimage)
        assertEquals(defaultAmount, openOrSplice.paymentAmount)
        // We don't update the payments DB: we're waiting to receive HTLCs after the open/splice.
        assertNull(paymentHandler.db.getIncomingPayment(paymentHash)?.received)
    }

    @Test
    fun `receive blinded payment with funding fee`() = runSuspendTest {
        val (paymentHandler, _, _) = createFixture(defaultAmount)
        val channelId = randomBytes32()
        val preimage = randomBytes32()
        val paymentHash = Crypto.sha256(preimage).toByteVector32()

        // We have a matching transaction in our DB, but the fees must be paid with a different payment_hash.
        val lease = LiquidityAds.Lease(
            defaultAmount.truncateToSatoshi() + LiquidityPolicy.minInboundLiquidityTarget,
            LiquidityAds.LeaseFees(2000.sat, 3000.sat),
            LiquidityAds.PaymentDetails.FromFutureHtlcWithPreimage(listOf(preimage)),
            randomBytes64(),
            LiquidityAds.FundingLeaseWitness.Basic(randomBytes(33).byteVector())
        )
        val purchase = InboundLiquidityOutgoingPayment(UUID.randomUUID(), channelId, TxId(randomBytes32()), 500.sat, lease, 0, null, null)
        paymentHandler.db.addOutgoingPayment(purchase)

        val cltvExpiry = TestConstants.Bob.nodeParams.minFinalCltvExpiryDelta.toCltvExpiry(TestConstants.defaultBlockHeight.toLong())
        val (finalPayload, route) = makeBlindedPayload(TestConstants.Bob.nodeParams.nodeId, defaultAmount, defaultAmount, cltvExpiry, preimage = preimage)
        val add = makeUpdateAddHtlc(0, randomBytes32(), paymentHandler, paymentHash, finalPayload, route.blindingKey, purchase.fundingFee)
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
        assertIs<IncomingPaymentHandler.ProcessAddResult.Accepted>(result)
        val fulfill = ChannelCommand.Htlc.Settlement.Fulfill(add.id, preimage, commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, fulfill)), result.actions.toSet())
        assertEquals(result.incomingPayment.received, result.received)
        assertEquals(defaultAmount - purchase.fundingFee.amount, result.received.amount)
        val receivedWith = IncomingPayment.ReceivedWith.LightningPayment(defaultAmount - purchase.fundingFee.amount, add.channelId, 0, purchase.fundingFee)
        assertEquals(listOf(receivedWith), result.received.receivedWith)
        checkDbPayment(result.incomingPayment, paymentHandler.db)
    }

    @Test
    fun `reject blinded payment for Bolt11 invoice`() = runSuspendTest {
        val (paymentHandler, incomingPayment, _) = createFixture(defaultAmount)
        val cltvExpiry = TestConstants.Bob.nodeParams.minFinalCltvExpiryDelta.toCltvExpiry(TestConstants.defaultBlockHeight.toLong())
        val (blindedPayload, route) = makeBlindedPayload(TestConstants.Bob.nodeParams.nodeId, defaultAmount, defaultAmount, cltvExpiry, preimage = incomingPayment.preimage)
        val add = makeUpdateAddHtlc(8, randomBytes32(), paymentHandler, incomingPayment.paymentHash, blindedPayload, route.blindingKey)
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)

        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        val expectedFailure = InvalidOnionBlinding(hash(add.onionRoutingPacket))
        val expected = ChannelCommand.Htlc.Settlement.FailMalformed(add.id, expectedFailure.onionHash, expectedFailure.code, commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
    }

    @Test
    fun `reject non-blinded payment for Bol12 invoice`() = runSuspendTest {
        val paymentHandler = IncomingPaymentHandler(TestConstants.Bob.nodeParams, InMemoryPaymentsDb(), TestConstants.fundingRates)
        val channelId = randomBytes32()
        val (amount1, amount2) = Pair(100_000_000.msat, 50_000_000.msat)
        val totalAmount = amount1 + amount2
        val preimage = randomBytes32()
        val paymentHash = Crypto.sha256(preimage).toByteVector32()
        val cltvExpiry = TestConstants.Bob.nodeParams.minFinalCltvExpiryDelta.toCltvExpiry(TestConstants.defaultBlockHeight.toLong())

        // Step 1 of 2:
        // - Alice sends first blinded multipart htlc to Bob
        // - Bob doesn't accept the MPP set yet
        run {
            val (finalPayload, route) = makeBlindedPayload(TestConstants.Bob.nodeParams.nodeId, amount1, totalAmount, cltvExpiry, preimage = preimage)
            val add = makeUpdateAddHtlc(0, channelId, paymentHandler, paymentHash, finalPayload, route.blindingKey)
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Pending>(result)
            assertNull(result.incomingPayment.received)
            assertTrue(result.actions.isEmpty())
        }

        // Step 2 of 2:
        // - Alice sends second multipart htlc to Bob without using blinded paths
        // - Bob rejects that htlc (the first htlc will be rejected after the MPP timeout)
        run {
            val add = makeUpdateAddHtlc(1, channelId, paymentHandler, paymentHash, makeMppPayload(amount2, totalAmount, randomBytes32()))
            val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)
            assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
            val expected = ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(totalAmount, TestConstants.defaultBlockHeight.toLong())), commit = true)
            assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
        }
    }

    @Test
    fun `reject blinded payment with amount too low`() = runSuspendTest {
        val paymentHandler = IncomingPaymentHandler(TestConstants.Bob.nodeParams, InMemoryPaymentsDb(), TestConstants.fundingRates)
        val cltvExpiry = TestConstants.Bob.nodeParams.minFinalCltvExpiryDelta.toCltvExpiry(TestConstants.defaultBlockHeight.toLong())
        val metadata = OfferPaymentMetadata.V1(randomBytes32(), 100_000_000.msat, randomBytes32(), randomKey().publicKey(), 1, currentTimestampMillis())
        val pathId = metadata.toPathId(TestConstants.Bob.nodeParams.nodePrivateKey)
        val amountTooLow = metadata.amount - 10_000_000.msat
        val (finalPayload, route) = makeBlindedPayload(TestConstants.Bob.nodeParams.nodeId, amountTooLow, amountTooLow, cltvExpiry, pathId)
        val add = makeUpdateAddHtlc(8, randomBytes32(), paymentHandler, metadata.paymentHash, finalPayload, route.blindingKey)
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)

        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        val expectedFailure = InvalidOnionBlinding(hash(add.onionRoutingPacket))
        val expected = ChannelCommand.Htlc.Settlement.FailMalformed(add.id, expectedFailure.onionHash, expectedFailure.code, commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
    }

    @Test
    fun `reject blinded payment with payment_hash mismatch`() = runSuspendTest {
        val paymentHandler = IncomingPaymentHandler(TestConstants.Bob.nodeParams, InMemoryPaymentsDb(), TestConstants.fundingRates)
        val cltvExpiry = TestConstants.Bob.nodeParams.minFinalCltvExpiryDelta.toCltvExpiry(TestConstants.defaultBlockHeight.toLong())
        val metadata = OfferPaymentMetadata.V1(randomBytes32(), 100_000_000.msat, randomBytes32(), randomKey().publicKey(), 1, currentTimestampMillis())
        val pathId = metadata.toPathId(TestConstants.Bob.nodeParams.nodePrivateKey)
        val (finalPayload, route) = makeBlindedPayload(TestConstants.Bob.nodeParams.nodeId, metadata.amount, metadata.amount, cltvExpiry, pathId)
        val add = makeUpdateAddHtlc(8, randomBytes32(), paymentHandler, metadata.paymentHash.reversed(), finalPayload, route.blindingKey)
        val result = paymentHandler.process(add, TestConstants.defaultBlockHeight, TestConstants.feeratePerKw)

        assertIs<IncomingPaymentHandler.ProcessAddResult.Rejected>(result)
        val expectedFailure = InvalidOnionBlinding(hash(add.onionRoutingPacket))
        val expected = ChannelCommand.Htlc.Settlement.FailMalformed(add.id, expectedFailure.onionHash, expectedFailure.code, commit = true)
        assertEquals(setOf(WrappedChannelCommand(add.channelId, expected)), result.actions.toSet())
    }

    companion object {
        val defaultPreimage = randomBytes32()
        val defaultPaymentHash = Crypto.sha256(defaultPreimage).toByteVector32()
        val defaultAmount = 150_000_000.msat

        private fun channelHops(destination: PublicKey): List<ChannelHop> {
            val dummyKey = PrivateKey(ByteVector32("0101010101010101010101010101010101010101010101010101010101010101")).publicKey()
            val dummyUpdate = ChannelUpdate(
                signature = ByteVector64.Zeroes,
                chainHash = BlockHash(ByteVector32.Zeroes),
                shortChannelId = ShortChannelId(144, 0, 0),
                timestampSeconds = 0,
                messageFlags = 0,
                channelFlags = 0,
                cltvExpiryDelta = CltvExpiryDelta(144),
                htlcMinimumMsat = 1000.msat,
                feeBaseMsat = 1.msat,
                feeProportionalMillionths = 10,
                htlcMaximumMsat = null
            )
            val channelHop = ChannelHop(dummyKey, destination, dummyUpdate)
            return listOf(channelHop)
        }

        private fun makeCmdAddHtlc(destination: PublicKey, paymentHash: ByteVector32, finalPayload: PaymentOnion.FinalPayload): ChannelCommand.Htlc.Add {
            return OutgoingPaymentPacket.buildCommand(UUID.randomUUID(), paymentHash, channelHops(destination), finalPayload).first.copy(commit = true)
        }

        private fun makeUpdateAddHtlc(
            id: Long,
            channelId: ByteVector32,
            destination: IncomingPaymentHandler,
            paymentHash: ByteVector32,
            finalPayload: PaymentOnion.FinalPayload,
            blinding: PublicKey? = null,
            fundingFee: LiquidityAds.FundingFee? = null
        ): UpdateAddHtlc {
            val destinationNodeId = when (blinding) {
                null -> destination.nodeParams.nodeId
                else -> RouteBlinding.derivePrivateKey(destination.nodeParams.nodePrivateKey, blinding).publicKey()
            }
            val (_, _, packetAndSecrets) = OutgoingPaymentPacket.buildPacket(paymentHash, channelHops(destinationNodeId), finalPayload, OnionRoutingPacket.PaymentPacketLength)
            val amount = finalPayload.amount - (fundingFee?.amount ?: 0.msat)
            return UpdateAddHtlc(channelId, id, amount, paymentHash, finalPayload.expiry, packetAndSecrets.packet, blinding, fundingFee)
        }

        private fun makeWillAddHtlc(destination: IncomingPaymentHandler, paymentHash: ByteVector32, finalPayload: PaymentOnion.FinalPayload, blinding: PublicKey? = null): WillAddHtlc {
            val destinationNodeId = when (blinding) {
                null -> destination.nodeParams.nodeId
                else -> RouteBlinding.derivePrivateKey(destination.nodeParams.nodePrivateKey, blinding).publicKey()
            }
            val (_, _, packetAndSecrets) = OutgoingPaymentPacket.buildPacket(paymentHash, channelHops(destinationNodeId), finalPayload, OnionRoutingPacket.PaymentPacketLength)
            return WillAddHtlc(destination.nodeParams.chainHash, randomBytes32(), finalPayload.amount, paymentHash, finalPayload.expiry, packetAndSecrets.packet, blinding)
        }

        private fun makeMppPayload(
            amount: MilliSatoshi,
            totalAmount: MilliSatoshi,
            paymentSecret: ByteVector32,
            cltvExpiryDelta: CltvExpiryDelta = CltvExpiryDelta(144),
            currentBlockHeight: Int = TestConstants.defaultBlockHeight
        ): PaymentOnion.FinalPayload.Standard {
            val expiry = cltvExpiryDelta.toCltvExpiry(currentBlockHeight.toLong())
            return PaymentOnion.FinalPayload.Standard.createMultiPartPayload(amount, totalAmount, expiry, paymentSecret, null)
        }

        private fun makeBlindedPayload(
            recipientNodeId: PublicKey,
            amount: MilliSatoshi,
            totalAmount: MilliSatoshi,
            cltvExpiry: CltvExpiry,
            offerId: ByteVector32 = randomBytes32(),
            quantity: Long = 1,
            preimage: ByteVector32 = randomBytes32(),
            payerKey: PublicKey = randomKey().publicKey()
        ): Pair<PaymentOnion.FinalPayload.Blinded, RouteBlinding.BlindedRoute> {
            val pathId = OfferPaymentMetadata.V1(offerId, totalAmount, preimage, payerKey, quantity, currentTimestampMillis()).toPathId(TestConstants.Bob.nodeParams.nodePrivateKey)
            val recipientData = RouteBlindingEncryptedData(TlvStream(RouteBlindingEncryptedDataTlv.PathId(pathId)))
            val route = RouteBlinding.create(randomKey(), listOf(recipientNodeId), listOf(recipientData.write().toByteVector())).route
            val payload = PaymentOnion.FinalPayload.Blinded(
                TlvStream(
                    OnionPaymentPayloadTlv.AmountToForward(amount),
                    OnionPaymentPayloadTlv.TotalAmount(totalAmount),
                    OnionPaymentPayloadTlv.OutgoingCltv(cltvExpiry),
                    OnionPaymentPayloadTlv.EncryptedRecipientData(route.encryptedPayloads.first())
                ), recipientData
            )
            return Pair(payload, route)
        }

        private fun makeBlindedPayload(
            recipientNodeId: PublicKey,
            amount: MilliSatoshi,
            totalAmount: MilliSatoshi,
            cltvExpiry: CltvExpiry,
            pathId: ByteVector
        ): Pair<PaymentOnion.FinalPayload.Blinded, RouteBlinding.BlindedRoute> {
            val recipientData = RouteBlindingEncryptedData(TlvStream(RouteBlindingEncryptedDataTlv.PathId(pathId)))
            val route = RouteBlinding.create(randomKey(), listOf(recipientNodeId), listOf(recipientData.write().toByteVector())).route
            val payload = PaymentOnion.FinalPayload.Blinded(
                TlvStream(
                    OnionPaymentPayloadTlv.AmountToForward(amount),
                    OnionPaymentPayloadTlv.TotalAmount(totalAmount),
                    OnionPaymentPayloadTlv.OutgoingCltv(cltvExpiry),
                    OnionPaymentPayloadTlv.EncryptedRecipientData(route.encryptedPayloads.first())
                ), recipientData
            )
            return Pair(payload, route)
        }

        private suspend fun makeIncomingPayment(payee: IncomingPaymentHandler, amount: MilliSatoshi?, expirySeconds: Long? = null, timestamp: Long = currentTimestampSeconds()): Pair<IncomingPayment, ByteVector32> {
            val paymentRequest = payee.createInvoice(defaultPreimage, amount, Either.Left("unit test"), listOf(), expirySeconds, timestamp)
            assertNotNull(paymentRequest.paymentMetadata)
            return Pair(payee.db.getIncomingPayment(paymentRequest.paymentHash)!!, paymentRequest.paymentSecret)
        }

        private suspend fun checkDbPayment(incomingPayment: IncomingPayment, db: IncomingPaymentsDb) {
            val dbPayment = db.getIncomingPayment(incomingPayment.paymentHash)!!
            assertEquals(incomingPayment.preimage, dbPayment.preimage)
            assertEquals(incomingPayment.paymentHash, dbPayment.paymentHash)
            assertEquals(incomingPayment.origin, dbPayment.origin)
            assertEquals(incomingPayment.amount, dbPayment.amount)
            assertEquals(incomingPayment.received?.receivedWith, dbPayment.received?.receivedWith)
        }

        private suspend fun createFixture(invoiceAmount: MilliSatoshi?, fundingRates: LiquidityAds.WillFundRates = TestConstants.fundingRates): Triple<IncomingPaymentHandler, IncomingPayment, ByteVector32> {
            val paymentHandler = IncomingPaymentHandler(TestConstants.Bob.nodeParams, InMemoryPaymentsDb(), fundingRates)
            // We use a liquidity policy that accepts payment values used by default in this test file.
            paymentHandler.nodeParams.liquidityPolicy.emit(LiquidityPolicy.Auto(inboundLiquidityTarget = null, maxAbsoluteFee = 5_000.sat, maxRelativeFeeBasisPoints = 500, skipAbsoluteFeeCheck = false))
            val (incomingPayment, paymentSecret) = makeIncomingPayment(paymentHandler, invoiceAmount)
            return Triple(paymentHandler, incomingPayment, paymentSecret)
        }

        private suspend fun createFeeCreditFixture(invoiceAmount: MilliSatoshi, policy: LiquidityPolicy): Triple<IncomingPaymentHandler, IncomingPayment, ByteVector32> {
            val nodeParams = TestConstants.Bob.nodeParams.copy(features = TestConstants.Bob.nodeParams.features.add(Feature.FundingFeeCredit to FeatureSupport.Optional))
            nodeParams.liquidityPolicy.emit(policy)
            val fundingRates = TestConstants.fundingRates.copy(paymentTypes = TestConstants.fundingRates.paymentTypes + LiquidityAds.PaymentType.FromFeeCredit)
            val paymentHandler = IncomingPaymentHandler(nodeParams, InMemoryPaymentsDb(), fundingRates)
            val (incomingPayment, paymentSecret) = makeIncomingPayment(paymentHandler, invoiceAmount)
            return Triple(paymentHandler, incomingPayment, paymentSecret)
        }
    }
}
