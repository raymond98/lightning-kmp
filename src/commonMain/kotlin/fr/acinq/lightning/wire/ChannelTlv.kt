package fr.acinq.lightning.wire

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.lightning.Features
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.ChannelType
import fr.acinq.lightning.channel.Origin
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.lightning.utils.toByteVector64

sealed class ChannelTlv : Tlv {
    /** Commitment to where the funds will go in case of a mutual close, which remote node will enforce in case we're compromised. */
    data class UpfrontShutdownScriptTlv(val scriptPubkey: ByteVector) : ChannelTlv() {
        val isEmpty: Boolean get() = scriptPubkey.isEmpty()

        override val tag: Long get() = UpfrontShutdownScriptTlv.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(scriptPubkey, out)
        }

        companion object : TlvValueReader<UpfrontShutdownScriptTlv> {
            const val tag: Long = 0

            override fun read(input: Input): UpfrontShutdownScriptTlv {
                val len = input.availableBytes
                val script = LightningCodecs.bytes(input, len)
                return UpfrontShutdownScriptTlv(ByteVector(script))
            }
        }
    }

    data class ChannelTypeTlv(val channelType: ChannelType) : ChannelTlv() {
        override val tag: Long get() = ChannelTypeTlv.tag

        override fun write(out: Output) {
            val features = when (channelType) {
                is ChannelType.SupportedChannelType -> channelType.toFeatures()
                is ChannelType.UnsupportedChannelType -> channelType.featureBits
            }
            LightningCodecs.writeBytes(features.toByteArray(), out)
        }

        companion object : TlvValueReader<ChannelTypeTlv> {
            const val tag: Long = 1

            override fun read(input: Input): ChannelTypeTlv {
                val len = input.availableBytes
                val features = LightningCodecs.bytes(input, len)
                return ChannelTypeTlv(ChannelType.fromFeatures(Features(features)))
            }
        }
    }

    object RequireConfirmedInputsTlv : ChannelTlv(), TlvValueReader<RequireConfirmedInputsTlv> {
        override val tag: Long get() = 2

        override fun write(out: Output) = Unit

        override fun read(input: Input): RequireConfirmedInputsTlv = this
    }

    /** Request inbound liquidity from our peer. */
    data class RequestFunds(val amount: Satoshi, val leaseDuration: Int, val leaseExpiry: Int) : ChannelTlv() {
        override val tag: Long get() = RequestFunds.tag

        override fun write(out: Output) {
            LightningCodecs.writeU64(amount.toLong(), out)
            LightningCodecs.writeU16(leaseDuration, out)
            LightningCodecs.writeU32(leaseExpiry, out)
        }

        companion object : TlvValueReader<RequestFunds> {
            const val tag: Long = 1337

            override fun read(input: Input): RequestFunds = RequestFunds(
                amount = LightningCodecs.u64(input).sat,
                leaseDuration = LightningCodecs.u16(input),
                leaseExpiry = LightningCodecs.u32(input),
            )
        }
    }

    /** Liquidity rates applied to an incoming [[RequestFunds]]. */
    data class WillFund(val sig: ByteVector64, val fundingWeight: Int, val leaseFeeProportional: Int, val leaseFeeBase: Satoshi, val maxRelayFeeProportional: Int, val maxRelayFeeBase: MilliSatoshi) : ChannelTlv() {
        override val tag: Long get() = WillFund.tag

        fun leaseRate(leaseDuration: Int): LiquidityAds.LeaseRate = LiquidityAds.LeaseRate(leaseDuration, fundingWeight, leaseFeeProportional, leaseFeeBase, maxRelayFeeProportional, maxRelayFeeBase)

        override fun write(out: Output) {
            LightningCodecs.writeBytes(sig, out)
            LightningCodecs.writeU16(fundingWeight, out)
            LightningCodecs.writeU16(leaseFeeProportional, out)
            LightningCodecs.writeU32(leaseFeeBase.sat.toInt(), out)
            LightningCodecs.writeU16(maxRelayFeeProportional, out)
            LightningCodecs.writeU32(maxRelayFeeBase.msat.toInt(), out)
        }

        companion object : TlvValueReader<WillFund> {
            const val tag: Long = 1337

            override fun read(input: Input): WillFund = WillFund(
                sig = LightningCodecs.bytes(input, 64).toByteVector64(),
                fundingWeight = LightningCodecs.u16(input),
                leaseFeeProportional = LightningCodecs.u16(input),
                leaseFeeBase = LightningCodecs.u32(input).sat,
                maxRelayFeeProportional = LightningCodecs.u16(input),
                maxRelayFeeBase = LightningCodecs.u32(input).msat,
            )
        }
    }

    data class OriginTlv(val origin: Origin) : ChannelTlv() {
        override val tag: Long get() = OriginTlv.tag

        override fun write(out: Output) {
            when (origin) {
                is Origin.PayToOpenOrigin -> {
                    LightningCodecs.writeU16(1, out)
                    LightningCodecs.writeBytes(origin.paymentHash, out)
                    LightningCodecs.writeU64(origin.miningFee.toLong(), out)
                    LightningCodecs.writeU64(origin.serviceFee.toLong(), out)
                    LightningCodecs.writeU64(origin.amount.toLong(), out)
                }

                is Origin.PleaseOpenChannelOrigin -> {
                    LightningCodecs.writeU16(4, out)
                    LightningCodecs.writeBytes(origin.requestId, out)
                    LightningCodecs.writeU64(origin.miningFee.toLong(), out)
                    LightningCodecs.writeU64(origin.serviceFee.toLong(), out)
                    LightningCodecs.writeU64(origin.amount.toLong(), out)
                }
            }
        }

        companion object : TlvValueReader<OriginTlv> {
            const val tag: Long = 0x47000005

            override fun read(input: Input): OriginTlv {
                val origin = when (LightningCodecs.u16(input)) {
                    1 -> Origin.PayToOpenOrigin(
                        paymentHash = LightningCodecs.bytes(input, 32).byteVector32(),
                        miningFee = LightningCodecs.u64(input).sat,
                        serviceFee = LightningCodecs.u64(input).msat,
                        amount = LightningCodecs.u64(input).msat
                    )

                    4 -> Origin.PleaseOpenChannelOrigin(
                        requestId = LightningCodecs.bytes(input, 32).byteVector32(),
                        miningFee = LightningCodecs.u64(input).sat,
                        serviceFee = LightningCodecs.u64(input).msat,
                        amount = LightningCodecs.u64(input).msat
                    )

                    else -> error("Unsupported channel origin discriminator")
                }
                return OriginTlv(origin)
            }
        }
    }

    /** With rbfed splices we can have multiple origins*/
    data class OriginsTlv(val origins: List<Origin>) : ChannelTlv() {
        override val tag: Long get() = OriginsTlv.tag

        override fun write(out: Output) {
            LightningCodecs.writeU16(origins.size, out)
            origins.forEach { OriginTlv(it).write(out) }
        }

        companion object : TlvValueReader<OriginsTlv> {
            const val tag: Long = 0x47000009

            override fun read(input: Input): OriginsTlv {
                val size = LightningCodecs.u16(input)
                val origins = buildList {
                    for (i in 0 until size) {
                        add(OriginTlv.read(input).origin)
                    }
                }
                return OriginsTlv(origins)
            }
        }
    }

    /** Amount that will be offered by the initiator of a dual-funded channel to the non-initiator. */
    data class PushAmountTlv(val amount: MilliSatoshi) : ChannelTlv() {
        override val tag: Long get() = PushAmountTlv.tag

        override fun write(out: Output) = LightningCodecs.writeTU64(amount.toLong(), out)

        companion object : TlvValueReader<PushAmountTlv> {
            const val tag: Long = 0x47000007

            override fun read(input: Input): PushAmountTlv = PushAmountTlv(LightningCodecs.tu64(input).msat)
        }
    }
}

sealed class ChannelReadyTlv : Tlv {
    data class ShortChannelIdTlv(val alias: ShortChannelId) : ChannelReadyTlv() {
        override val tag: Long get() = ShortChannelIdTlv.tag
        override fun write(out: Output) = LightningCodecs.writeU64(alias.toLong(), out)

        companion object : TlvValueReader<ShortChannelIdTlv> {
            const val tag: Long = 1
            override fun read(input: Input): ShortChannelIdTlv = ShortChannelIdTlv(ShortChannelId(LightningCodecs.u64(input)))
        }
    }
}

sealed class CommitSigTlv : Tlv {
    data class ChannelData(val ecb: EncryptedChannelData) : CommitSigTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }

    data class AlternativeFeerateSig(val feerate: FeeratePerKw, val sig: ByteVector64)

    /**
     * When there are no pending HTLCs, we provide a list of signatures for the commitment transaction signed at various feerates.
     * This gives more options to the remote node to recover their funds if the user disappears without closing channels.
     */
    data class AlternativeFeerateSigs(val sigs: List<AlternativeFeerateSig>) : CommitSigTlv() {
        override val tag: Long get() = AlternativeFeerateSigs.tag
        override fun write(out: Output) {
            LightningCodecs.writeByte(sigs.size, out)
            sigs.forEach {
                LightningCodecs.writeU32(it.feerate.toLong().toInt(), out)
                LightningCodecs.writeBytes(it.sig, out)
            }
        }

        companion object : TlvValueReader<AlternativeFeerateSigs> {
            const val tag: Long = 0x47010001
            override fun read(input: Input): AlternativeFeerateSigs {
                val count = LightningCodecs.byte(input)
                val sigs = (0 until count).map {
                    AlternativeFeerateSig(
                        FeeratePerKw(LightningCodecs.u32(input).toLong().sat),
                        LightningCodecs.bytes(input, 64).toByteVector64()
                    )
                }
                return AlternativeFeerateSigs(sigs)
            }
        }
    }

    data class Batch(val size: Int) : CommitSigTlv() {
        override val tag: Long get() = Batch.tag
        override fun write(out: Output) = LightningCodecs.writeTU16(size, out)

        companion object : TlvValueReader<Batch> {
            const val tag: Long = 0x47010005
            override fun read(input: Input): Batch = Batch(size = LightningCodecs.tu16(input))
        }
    }
}

sealed class RevokeAndAckTlv : Tlv {
    data class ChannelData(val ecb: EncryptedChannelData) : RevokeAndAckTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}

sealed class ChannelReestablishTlv : Tlv {
    data class NextFunding(val txId: TxId) : ChannelReestablishTlv() {
        override val tag: Long get() = NextFunding.tag
        override fun write(out: Output) = LightningCodecs.writeTxHash(TxHash(txId), out)

        companion object : TlvValueReader<NextFunding> {
            const val tag: Long = 0
            override fun read(input: Input): NextFunding = NextFunding(TxId(LightningCodecs.txHash(input)))
        }
    }

    data class ChannelData(val ecb: EncryptedChannelData) : ChannelReestablishTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}

sealed class ShutdownTlv : Tlv {
    data class ChannelData(val ecb: EncryptedChannelData) : ShutdownTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}

sealed class ClosingCompleteTlv : Tlv {
    /** Signature for a closing transaction containing only the closer's output. */
    data class CloserNoClosee(val sig: ByteVector64) : ClosingCompleteTlv() {
        override val tag: Long get() = CloserNoClosee.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(sig.toByteArray(), out)

        companion object : TlvValueReader<CloserNoClosee> {
            const val tag: Long = 1
            override fun read(input: Input): CloserNoClosee = CloserNoClosee(LightningCodecs.bytes(input, 64).toByteVector64())
        }
    }

    /** Signature for a closing transaction containing only the closee's output. */
    data class NoCloserClosee(val sig: ByteVector64) : ClosingCompleteTlv() {
        override val tag: Long get() = NoCloserClosee.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(sig.toByteArray(), out)

        companion object : TlvValueReader<NoCloserClosee> {
            const val tag: Long = 2
            override fun read(input: Input): NoCloserClosee = NoCloserClosee(LightningCodecs.bytes(input, 64).toByteVector64())
        }
    }

    /** Signature for a closing transaction containing the closer and closee's outputs. */
    data class CloserAndClosee(val sig: ByteVector64) : ClosingCompleteTlv() {
        override val tag: Long get() = CloserAndClosee.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(sig.toByteArray(), out)

        companion object : TlvValueReader<CloserAndClosee> {
            const val tag: Long = 3
            override fun read(input: Input): CloserAndClosee = CloserAndClosee(LightningCodecs.bytes(input, 64).toByteVector64())
        }
    }

    data class ChannelData(val ecb: EncryptedChannelData) : ClosingCompleteTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}

sealed class ClosingSigTlv : Tlv {
    /** Signature for a closing transaction containing only the closer's output. */
    data class CloserNoClosee(val sig: ByteVector64) : ClosingSigTlv() {
        override val tag: Long get() = CloserNoClosee.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(sig.toByteArray(), out)

        companion object : TlvValueReader<CloserNoClosee> {
            const val tag: Long = 1
            override fun read(input: Input): CloserNoClosee = CloserNoClosee(LightningCodecs.bytes(input, 64).toByteVector64())
        }
    }

    /** Signature for a closing transaction containing only the closee's output. */
    data class NoCloserClosee(val sig: ByteVector64) : ClosingSigTlv() {
        override val tag: Long get() = NoCloserClosee.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(sig.toByteArray(), out)

        companion object : TlvValueReader<NoCloserClosee> {
            const val tag: Long = 2
            override fun read(input: Input): NoCloserClosee = NoCloserClosee(LightningCodecs.bytes(input, 64).toByteVector64())
        }
    }

    /** Signature for a closing transaction containing the closer and closee's outputs. */
    data class CloserAndClosee(val sig: ByteVector64) : ClosingSigTlv() {
        override val tag: Long get() = CloserAndClosee.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(sig.toByteArray(), out)

        companion object : TlvValueReader<CloserAndClosee> {
            const val tag: Long = 3
            override fun read(input: Input): CloserAndClosee = CloserAndClosee(LightningCodecs.bytes(input, 64).toByteVector64())
        }
    }

    data class ChannelData(val ecb: EncryptedChannelData) : ClosingSigTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}

sealed class PleaseOpenChannelTlv : Tlv {
    // NB: this is a temporary tlv that is only used to ensure a smooth migration to lightning-kmp for the android version of Phoenix.
    data class GrandParents(val outpoints: List<OutPoint>) : PleaseOpenChannelTlv() {
        override val tag: Long get() = GrandParents.tag
        override fun write(out: Output) {
            outpoints.forEach { outpoint ->
                LightningCodecs.writeTxHash(outpoint.hash, out)
                LightningCodecs.writeU64(outpoint.index, out)
            }
        }

        companion object : TlvValueReader<GrandParents> {
            const val tag: Long = 561
            override fun read(input: Input): GrandParents {
                val count = input.availableBytes / 40
                val outpoints = (0 until count).map { OutPoint(LightningCodecs.txHash(input), LightningCodecs.u64(input)) }
                return GrandParents(outpoints)
            }
        }
    }
}

sealed class PleaseOpenChannelRejectedTlv : Tlv {
    data class ExpectedFees(val fees: MilliSatoshi) : PleaseOpenChannelRejectedTlv() {
        override val tag: Long get() = ExpectedFees.tag
        override fun write(out: Output) = LightningCodecs.writeTU64(fees.toLong(), out)

        companion object : TlvValueReader<ExpectedFees> {
            const val tag: Long = 1
            override fun read(input: Input): ExpectedFees = ExpectedFees(LightningCodecs.tu64(input).msat)
        }
    }
}