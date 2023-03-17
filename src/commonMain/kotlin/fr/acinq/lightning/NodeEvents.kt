package fr.acinq.lightning

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Satoshi
import fr.acinq.lightning.channel.ChannelStateWithCommitments
import fr.acinq.lightning.channel.Normal
import fr.acinq.lightning.channel.WaitForFundingCreated
import fr.acinq.lightning.wire.PleaseOpenChannel
import fr.acinq.lightning.wire.PleaseOpenChannelFailure
import kotlinx.coroutines.CompletableDeferred

sealed interface NodeEvents

sealed interface SwapInEvents : NodeEvents {
    data class Requested(val req: PleaseOpenChannel) : SwapInEvents
    data class Accepted(val requestId: ByteVector32, val serviceFee: MilliSatoshi, val miningFee: Satoshi) : SwapInEvents
    data class Rejected(val requestId: ByteVector32, val failure: PleaseOpenChannelFailure, val requiredFees: MilliSatoshi?) : SwapInEvents
}

sealed interface ChannelEvents : NodeEvents {
    data class Creating(val state: WaitForFundingCreated) : ChannelEvents
    data class Created(val state: ChannelStateWithCommitments) : ChannelEvents
    data class Confirmed(val state: Normal) : ChannelEvents
}

sealed interface LiquidityEvents : NodeEvents {
    val amount: MilliSatoshi
    val fee: MilliSatoshi
    val source: Source

    enum class Source { ONCHAIN_WALLET, OFFCHAIN_PAYMENT }
    data class Rejected(override val amount: MilliSatoshi, override val fee: MilliSatoshi, override val source: Source, val reason: Reason) : LiquidityEvents {
        sealed class Reason {
            object PolicySetToDisabled : Reason()
            object RejectedByUser : Reason()
            data class TooExpensive(val maxAllowed: MilliSatoshi, val actual: MilliSatoshi) : Reason()
        }
    }

    data class ApprovalRequested(override val amount: MilliSatoshi, override val fee: MilliSatoshi, override val source: Source, val replyTo: CompletableDeferred<Boolean>) : LiquidityEvents
}
