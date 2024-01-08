package fr.acinq.lightning.payment

import fr.acinq.bitcoin.Satoshi
import fr.acinq.lightning.LiquidityEvents
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.utils.MDCLogger
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.toMilliSatoshi


sealed class LiquidityPolicy {
    /** Never initiates swap-ins, never accept pay-to-open */
    data object Disable : LiquidityPolicy()

    /**
     * Allow automated liquidity managements, within relative and absolute fee limits. Both conditions must be met.
     * @param maxAbsoluteFee max absolute fee
     * @param maxRelativeFeeBasisPoints max relative fee (all included: service fee and mining fee) (1_000 bips = 10 %)
     * @param skipAbsoluteFeeCheck only applies for off-chain payments, being more lax may make sense when the sender doesn't retry payments
     */
    data class Auto(val maxAbsoluteFee: Satoshi, val maxRelativeFeeBasisPoints: Int, val skipAbsoluteFeeCheck: Boolean) : LiquidityPolicy()

    /** Make decision for a particular liquidity event */
    fun maybeReject(amount: MilliSatoshi, fee: MilliSatoshi, source: LiquidityEvents.Source, logger: MDCLogger): LiquidityEvents.Rejected? {
        return when (this) {
            is Disable -> LiquidityEvents.Rejected.Reason.PolicySetToDisabled
            is Auto -> {
                val maxAbsoluteFee = if (skipAbsoluteFeeCheck && source == LiquidityEvents.Source.OffChainPayment) Long.MAX_VALUE.msat else this.maxAbsoluteFee.toMilliSatoshi()
                val maxRelativeFee = amount * maxRelativeFeeBasisPoints / 10_000
                logger.info { "liquidity policy check: fee=$fee maxAbsoluteFee=$maxAbsoluteFee maxRelativeFee=$maxRelativeFee policy=$this" }
                if (fee > maxRelativeFee) {
                    LiquidityEvents.Rejected.Reason.TooExpensive.OverRelativeFee(maxRelativeFeeBasisPoints)
                } else if (fee > maxAbsoluteFee) {
                    LiquidityEvents.Rejected.Reason.TooExpensive.OverAbsoluteFee(this.maxAbsoluteFee)
                } else null
            }
        }?.let { reason -> LiquidityEvents.Rejected(amount, fee, source, reason) }
    }

}