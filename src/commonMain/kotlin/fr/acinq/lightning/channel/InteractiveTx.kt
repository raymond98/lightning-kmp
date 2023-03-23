package fr.acinq.lightning.channel

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.Script.tail
import fr.acinq.lightning.blockchain.electrum.WalletState
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*

/**
 * Created by t-bast on 22/08/2022.
 */

/** An input that is already shared between participants (e.g. the current funding output when doing a splice). */
sealed class SharedFundingInput {
    abstract val info: Transactions.InputInfo
    abstract val weight: Long
    abstract fun sign(keyManager: KeyManager, localParams: LocalParams, tx: Transaction): ByteVector64

    data class Multisig2of2(override val info: Transactions.InputInfo, val localFundingPubkey: PublicKey, val remoteFundingPubkey: PublicKey) : SharedFundingInput() {

        constructor(keyManager: KeyManager, params: ChannelParams, commitment: Commitment) : this(
            info = commitment.commitInput,
            localFundingPubkey = keyManager.fundingPublicKey(params.localParams.fundingKeyPath).publicKey,
            remoteFundingPubkey = params.remoteParams.fundingPubKey
        )

        // This value was computed assuming 73 bytes signatures (worst-case scenario).
        override val weight: Long = Multisig2of2.weight

        override fun sign(keyManager: KeyManager, localParams: LocalParams, tx: Transaction): ByteVector64 {
            val fundingKey = keyManager.channelKeys(localParams.fundingKeyPath).fundingPrivateKey
            return keyManager.sign(Transactions.TransactionWithInputInfo.SpliceTx(info, tx), fundingKey)
        }

        companion object {
            const val weight: Long = 388
        }
    }
}

/**
 * @param channelId id of the channel.
 * @param isInitiator true if we initiated the protocol, in which case we will pay fees for the shared parts of the transaction.
 * @param localAmount amount contributed by us to the shared output.
 * @param remoteAmount amount contributed by our peer to the shared output.
 * @param sharedInput previous input shared between the two participants (e.g. previous funding output when splicing).
 * @param fundingPubkeyScript script of the shared output.
 * @param localOutputs outputs to be added to the shared transaction (e.g. splice-out).
 * @param lockTime transaction lock time.
 * @param dustLimit outputs below this value are considered invalid.
 * @param targetFeerate transaction feerate.
 */
data class InteractiveTxParams(
    val channelId: ByteVector32,
    val isInitiator: Boolean,
    val localAmount: Satoshi,
    val remoteAmount: Satoshi,
    val sharedInput: SharedFundingInput?,
    val fundingPubkeyScript: ByteVector,
    val localOutputs: List<TxOut>,
    val lockTime: Long,
    val dustLimit: Satoshi,
    val targetFeerate: FeeratePerKw
) {
    constructor(channelId: ByteVector32, isInitiator: Boolean, localAmount: Satoshi, remoteAmount: Satoshi, fundingPubkeyScript: ByteVector, lockTime: Long, dustLimit: Satoshi, targetFeerate: FeeratePerKw) :
            this(channelId, isInitiator, localAmount, remoteAmount, null, fundingPubkeyScript, listOf(), lockTime, dustLimit, targetFeerate)

    init {
        require(localAmount >= 0.sat && remoteAmount >= 0.sat) { "funding amount cannot be negative" }
    }

    val fundingAmount: Satoshi = localAmount + remoteAmount

    // BOLT 2: MUST set `feerate` greater than or equal to 25/24 times the `feerate` of the previously constructed transaction, rounded down.
    val minNextFeerate: FeeratePerKw = targetFeerate * 25 / 24

    // BOLT 2: the initiator's serial IDs MUST use even values and the non-initiator odd values.
    val serialIdParity = if (isInitiator) 0 else 1

    companion object {
        fun computeLocalContribution(isInitiator: Boolean, commitment: Commitment, spliceIn: List<WalletState.Utxo>, spliceOut: List<TxOut>, targetFeerate: FeeratePerKw): Satoshi {
            val commonFieldsWeight = if (isInitiator) {
                val dummyTx = Transaction(
                    version = 2,
                    txIn = emptyList(), // NB: we add the weight manually
                    txOut = listOf(commitment.commitInput.txOut), // we're taking the previous output, it has the wrong amount but we don't care: only the weight matters to compute fees
                    lockTime = 0
                )
                dummyTx.weight() + SharedFundingInput.Multisig2of2.weight
            } else 0
            val spliceInputsWeight = spliceIn.size * Transactions.p2wpkhInputWeight
            val spliceOutputsWeight = spliceOut.sumOf { it.weight() }
            val weight = commonFieldsWeight + spliceInputsWeight + spliceOutputsWeight
            val fees = Transactions.weight2fee(targetFeerate, weight.toInt())
            return commitment.localCommit.spec.toLocal.truncateToSatoshi() + spliceIn.map { it.amount }.sum() - spliceOut.map { it.amount }.sum() - fees
        }
    }
}

sealed class InteractiveTxInput {
    abstract val serialId: Long
    abstract val outPoint: OutPoint
    abstract val sequence: UInt

    sealed interface Outgoing
    sealed interface Incoming

    /** A local-only input that funds the interactive transaction. */
    data class Local(override val serialId: Long, val previousTx: Transaction, val previousTxOutput: Long, override val sequence: UInt) : InteractiveTxInput(), Outgoing {
        override val outPoint: OutPoint = OutPoint(previousTx, previousTxOutput)
    }

    /**
     * A remote-only input that funds the interactive transaction.
     * We only keep the data we need from our peer's TxAddInput to avoid storing potentially large messages in our DB.
     */
    data class Remote(override val serialId: Long, override val outPoint: OutPoint, val txOut: TxOut, override val sequence: UInt) : InteractiveTxInput(), Incoming

    /** The shared input can be added by us or by our peer, depending on who initiated the protocol. */
    data class Shared(override val serialId: Long, override val outPoint: OutPoint, override val sequence: UInt, val localAmount: Satoshi, val remoteAmount: Satoshi) : InteractiveTxInput(), Incoming, Outgoing
}

sealed class InteractiveTxOutput {
    abstract val serialId: Long
    abstract val amount: Satoshi
    abstract val pubkeyScript: ByteVector

    sealed interface Outgoing
    sealed interface Incoming

    /** A local-only output of the interactive transaction. */
    sealed class Local : InteractiveTxOutput(), Outgoing {
        data class Change(override val serialId: Long, override val amount: Satoshi, override val pubkeyScript: ByteVector) : Local()
        data class NonChange(override val serialId: Long, override val amount: Satoshi, override val pubkeyScript: ByteVector) : Local()
    }

    /**
     * A remote-only output of the interactive transaction.
     * We only keep the data we need from our peer's TxAddOutput to avoid storing potentially large messages in our DB.
     */
    data class Remote(override val serialId: Long, override val amount: Satoshi, override val pubkeyScript: ByteVector) : InteractiveTxOutput(), Incoming

    /** The shared output can be added by us or by our peer, depending on who initiated the protocol. */
    data class Shared(override val serialId: Long, override val pubkeyScript: ByteVector, val localAmount: Satoshi, val remoteAmount: Satoshi) : InteractiveTxOutput(), Incoming, Outgoing {
        override val amount: Satoshi = localAmount + remoteAmount
    }
}

sealed class FundingContributionFailure {
    // @formatter:off
    data class InputOutOfBounds(val txId: ByteVector32, val outputIndex: Int) : FundingContributionFailure() { override fun toString(): String = "invalid input $txId:$outputIndex (out of bounds)" }
    data class NonPay2wpkhInput(val txId: ByteVector32, val outputIndex: Int) : FundingContributionFailure() { override fun toString(): String = "invalid input $txId:$outputIndex (must use p2wpkh)" }
    data class InputBelowDust(val txId: ByteVector32, val outputIndex: Int, val amount: Satoshi, val dustLimit: Satoshi) : FundingContributionFailure() { override fun toString(): String = "invalid input $txId:$outputIndex (below dust: amount=$amount, dust=$dustLimit)" }
    data class InputTxTooLarge(val tx: Transaction) : FundingContributionFailure() { override fun toString(): String = "invalid input tx ${tx.txid} (too large)" }
    data class NotEnoughFunding(val fundingAmount: Satoshi, val nonFundingAmount: Satoshi, val providedAmount: Satoshi) : FundingContributionFailure() { override fun toString(): String = "not enough funds provided (expected at least $fundingAmount + $nonFundingAmount, got $providedAmount)" }
    data class NotEnoughFees(val currentFees: Satoshi, val expectedFees: Satoshi) : FundingContributionFailure() { override fun toString(): String = "not enough funds to pay fees (expected at least $expectedFees, got $currentFees)" }
    // @formatter:on
}

/** Inputs and outputs we contribute to the funding transaction. */
data class FundingContributions(val inputs: List<InteractiveTxInput.Outgoing>, val outputs: List<InteractiveTxOutput.Outgoing>) {
    companion object {
        /**
         * @param walletUtxos p2wpkh wallet inputs.
         */
        fun create(params: InteractiveTxParams, walletUtxos: List<WalletState.Utxo>): Either<FundingContributionFailure, FundingContributions> = create(params, null, walletUtxos, listOf())

        /**
         * @param sharedUtxo previous input shared between the two participants (e.g. previous funding output when splicing) and our corresponding balance.
         * @param walletUtxos p2wpkh wallet inputs.
         * @param localOutputs outputs to be added to the shared transaction (e.g. splice-out).
         * @param changePubKey if provided, a corresponding p2wpkh change output will be created.
         */
        fun create(
            params: InteractiveTxParams,
            sharedUtxo: Pair<SharedFundingInput, Satoshi>?,
            walletUtxos: List<WalletState.Utxo>,
            localOutputs: List<TxOut>,
            changePubKey: PublicKey? = null
        ): Either<FundingContributionFailure, FundingContributions> {
            walletUtxos.forEach { (tx, txOutput) ->
                if (tx.txOut.size <= txOutput) return Either.Left(FundingContributionFailure.InputOutOfBounds(tx.txid, txOutput))
                if (tx.txOut[txOutput].amount < params.dustLimit) return Either.Left(FundingContributionFailure.InputBelowDust(tx.txid, txOutput, tx.txOut[txOutput].amount, params.dustLimit))
                if (!Script.isPay2wpkh(tx.txOut[txOutput].publicKeyScript.toByteArray())) return Either.Left(FundingContributionFailure.NonPay2wpkhInput(tx.txid, txOutput))
                if (Transaction.write(tx).size > 65_000) return Either.Left(FundingContributionFailure.InputTxTooLarge(tx))
            }
            val totalAmountIn = walletUtxos.map { it.amount }.sum() + (sharedUtxo?.second ?: 0.sat)
            val totalAmountOut = params.localAmount + localOutputs.map { it.amount }.sum()
            if (totalAmountIn < totalAmountOut) {
                return Either.Left(FundingContributionFailure.NotEnoughFunding(params.localAmount, localOutputs.map { it.amount }.sum(), totalAmountIn))
            }

            // We compute the fees that we should pay in the shared transaction.
            val dummyWalletWitness = Script.witnessPay2wpkh(Transactions.PlaceHolderPubKey, Scripts.der(Transactions.PlaceHolderSig, SigHash.SIGHASH_ALL))
            val dummySignedWalletTxIn = walletUtxos.map { TxIn(it.outPoint, ByteVector.empty, 0, dummyWalletWitness) }
            val dummyChangeTxOut = TxOut(params.localAmount, Script.pay2wpkh(Transactions.PlaceHolderPubKey))
            val sharedTxOut = TxOut(params.fundingAmount, params.fundingPubkeyScript)
            val (weightWithoutChange, weightWithChange) = when (params.isInitiator) {
                true -> {
                    // The initiator must add the shared input, the shared output and pay for the fees of the common transaction fields.
                    val sharedInputWeight = sharedUtxo?.first?.weight?.toInt() ?: 0
                    val w1 = Transaction(2, dummySignedWalletTxIn, localOutputs + listOf(sharedTxOut), 0).weight()
                    val w2 = Transaction(2, dummySignedWalletTxIn, localOutputs + listOf(sharedTxOut, dummyChangeTxOut), 0).weight()
                    Pair(w1 + sharedInputWeight, w2 + sharedInputWeight)
                }
                false -> {
                    // The non-initiator only pays for the weights of their own inputs and outputs.
                    val emptyTx = Transaction(2, listOf(), listOf(), 0)
                    val w1 = Transaction(2, dummySignedWalletTxIn, localOutputs, 0).weight() - emptyTx.weight()
                    val w2 = Transaction(2, dummySignedWalletTxIn, localOutputs + listOf(dummyChangeTxOut), 0).weight() - emptyTx.weight()
                    Pair(w1, w2)
                }
            }
            // If we're not the initiator, we don't return an error when we're unable to meet the desired feerate.
            val feesWithoutChange = totalAmountIn - totalAmountOut
            if (params.isInitiator && feesWithoutChange < Transactions.weight2fee(params.targetFeerate, weightWithoutChange)) {
                return Either.Left(FundingContributionFailure.NotEnoughFees(feesWithoutChange, Transactions.weight2fee(params.targetFeerate, weightWithoutChange)))
            }

            val sharedOutput = listOf(InteractiveTxOutput.Shared(0, params.fundingPubkeyScript, params.localAmount, params.remoteAmount))
            val nonChangeOutputs = localOutputs.map { o -> InteractiveTxOutput.Local.NonChange(0, o.amount, o.publicKeyScript) }
            val changeOutput = when (changePubKey) {
                null -> listOf()
                else -> {
                    val changeAmount = totalAmountIn - totalAmountOut - Transactions.weight2fee(params.targetFeerate, weightWithChange)
                    if (params.dustLimit <= changeAmount) {
                        listOf(InteractiveTxOutput.Local.Change(0, changeAmount, Script.write(Script.pay2wpkh(changePubKey)).byteVector()))
                    } else {
                        listOf()
                    }
                }
            }
            val sharedInput = sharedUtxo?.let { (i, localAmount) -> listOf(InteractiveTxInput.Shared(0, i.info.outPoint, 0xfffffffdU, localAmount, i.info.txOut.amount - localAmount)) } ?: listOf()
            val walletInputs = walletUtxos.map { i -> InteractiveTxInput.Local(0, i.previousTx, i.outputIndex.toLong(), 0xfffffffdU) }
            return if (params.isInitiator) {
                Either.Right(sortFundingContributions(params, sharedInput + walletInputs, sharedOutput + nonChangeOutputs + changeOutput))
            } else {
                Either.Right(sortFundingContributions(params, walletInputs, nonChangeOutputs + changeOutput))
            }
        }

        private fun sortFundingContributions(params: InteractiveTxParams, inputs: List<InteractiveTxInput.Outgoing>, outputs: List<InteractiveTxOutput.Outgoing>): FundingContributions {
            // We always randomize the order of inputs and outputs.
            val sortedInputs = inputs.shuffled().mapIndexed { i, input ->
                val serialId = 2 * i.toLong() + params.serialIdParity
                when (input) {
                    is InteractiveTxInput.Local -> input.copy(serialId = serialId)
                    is InteractiveTxInput.Shared -> input.copy(serialId = serialId)
                }
            }
            val sortedOutputs = outputs.shuffled().mapIndexed { i, output ->
                val serialId = 2 * (i + inputs.size).toLong() + params.serialIdParity
                when (output) {
                    is InteractiveTxOutput.Local.Change -> output.copy(serialId = serialId)
                    is InteractiveTxOutput.Local.NonChange -> output.copy(serialId = serialId)
                    is InteractiveTxOutput.Shared -> output.copy(serialId = serialId)
                }
            }
            return FundingContributions(sortedInputs, sortedOutputs)
        }
    }
}

/** Unsigned transaction created collaboratively. */
data class SharedTransaction(
    val sharedInput: InteractiveTxInput.Shared?, val sharedOutput: InteractiveTxOutput.Shared,
    val localInputs: List<InteractiveTxInput.Local>, val remoteInputs: List<InteractiveTxInput.Remote>,
    val localOutputs: List<InteractiveTxOutput.Local>, val remoteOutputs: List<InteractiveTxOutput.Remote>,
    val lockTime: Long
) {
    val localAmountIn: Satoshi = (sharedInput?.localAmount ?: 0.sat) + localInputs.map { i -> i.previousTx.txOut[i.previousTxOutput.toInt()].amount }.sum()
    val remoteAmountIn: Satoshi = (sharedInput?.remoteAmount ?: 0.sat) + remoteInputs.map { i -> i.txOut.amount }.sum()
    val totalAmountIn: Satoshi = localAmountIn + remoteAmountIn
    val localAmountOut: Satoshi = sharedOutput.localAmount + localOutputs.map { o -> o.amount }.sum()
    val remoteAmountOut: Satoshi = sharedOutput.remoteAmount + remoteOutputs.map { o -> o.amount }.sum()
    val localFees: Satoshi = localAmountIn - localAmountOut
    val remoteFees: Satoshi = remoteAmountIn - remoteAmountOut
    val fees: Satoshi = localFees + remoteFees

    fun buildUnsignedTx(): Transaction {
        val sharedTxIn = sharedInput?.let { i -> listOf(Pair(i.serialId, TxIn(i.outPoint, ByteVector.empty, i.sequence.toLong()))) } ?: listOf()
        val localTxIn = localInputs.map { i -> Pair(i.serialId, TxIn(OutPoint(i.previousTx, i.previousTxOutput), ByteVector.empty, i.sequence.toLong())) }
        val remoteTxIn = remoteInputs.map { i -> Pair(i.serialId, TxIn(i.outPoint, ByteVector.empty, i.sequence.toLong())) }
        val inputs = (sharedTxIn + localTxIn + remoteTxIn).sortedBy { (serialId, _) -> serialId }.map { (_, txIn) -> txIn }
        val sharedTxOut = listOf(Pair(sharedOutput.serialId, TxOut(sharedOutput.amount, sharedOutput.pubkeyScript)))
        val localTxOut = localOutputs.map { o -> Pair(o.serialId, TxOut(o.amount, o.pubkeyScript)) }
        val remoteTxOut = remoteOutputs.map { o -> Pair(o.serialId, TxOut(o.amount, o.pubkeyScript)) }
        val outputs = (sharedTxOut + localTxOut + remoteTxOut).sortedBy { (serialId, _) -> serialId }.map { (_, txOut) -> txOut }
        return Transaction(2, inputs, outputs, lockTime)
    }

    fun sign(keyManager: KeyManager, fundingParams: InteractiveTxParams, localParams: LocalParams): PartiallySignedSharedTransaction? {
        val unsignedTx = buildUnsignedTx()
        val sharedSig = fundingParams.sharedInput?.sign(keyManager, localParams, unsignedTx)
        val localSigs = unsignedTx.txIn.mapIndexed { i, txIn ->
            localInputs
                .find { input -> txIn.outPoint == OutPoint(input.previousTx, input.previousTxOutput) }
                ?.let { input -> WalletState.signInput(keyManager, unsignedTx, i, input.previousTx.txOut[input.previousTxOutput.toInt()]).second }
        }.filterNotNull()
        return when (localSigs.size) {
            localInputs.size -> PartiallySignedSharedTransaction(this, TxSignatures(fundingParams.channelId, unsignedTx, localSigs, sharedSig))
            else -> null // We couldn't sign all of our inputs, most likely the caller didn't provide the right set of utxos.
        }
    }
}

/** Signed transaction created collaboratively. */
sealed class SignedSharedTransaction {
    abstract val txId: ByteVector32
    abstract val tx: SharedTransaction
    abstract val localSigs: TxSignatures
    abstract val signedTx: Transaction?
}

data class PartiallySignedSharedTransaction(override val tx: SharedTransaction, override val localSigs: TxSignatures) : SignedSharedTransaction() {
    override val txId: ByteVector32 = localSigs.txId
    override val signedTx = null

    fun addRemoteSigs(fundingParams: InteractiveTxParams, remoteSigs: TxSignatures): FullySignedSharedTransaction? {
        if (localSigs.witnesses.size != tx.localInputs.size) {
            return null
        }
        if (remoteSigs.witnesses.size != tx.remoteInputs.size) {
            return null
        }
        if (remoteSigs.txId != localSigs.txId) {
            return null
        }
        val sharedSigs = fundingParams.sharedInput?.let {
            when (it) {
                is SharedFundingInput.Multisig2of2 -> Scripts.witness2of2(
                    localSigs.previousFundingTxSig ?: return null,
                    remoteSigs.previousFundingTxSig ?: return null,
                    it.localFundingPubkey,
                    it.remoteFundingPubkey,
                )
            }
        }
        val fullySignedTx = FullySignedSharedTransaction(tx, localSigs, remoteSigs, sharedSigs)
        val sharedOutput = fundingParams.sharedInput?.let { i -> mapOf(i.info.outPoint to i.info.txOut) } ?: mapOf()
        val localOutputs = tx.localInputs.associate { i -> OutPoint(i.previousTx, i.previousTxOutput) to i.previousTx.txOut[i.previousTxOutput.toInt()] }
        val remoteOutputs = tx.remoteInputs.associate { i -> i.outPoint to i.txOut }
        val previousOutputs = sharedOutput + localOutputs + remoteOutputs
        return when (runTrying { Transaction.correctlySpends(fullySignedTx.signedTx, previousOutputs, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }) {
            is Try.Success -> fullySignedTx
            is Try.Failure -> null
        }
    }
}

data class FullySignedSharedTransaction(override val tx: SharedTransaction, override val localSigs: TxSignatures, val remoteSigs: TxSignatures, val sharedSigs: ScriptWitness?) : SignedSharedTransaction() {
    override val signedTx = run {
        val sharedTxIn = tx.sharedInput?.let { i -> listOf(Pair(i.serialId, TxIn(i.outPoint, ByteVector.empty, i.sequence.toLong(), sharedSigs ?: ScriptWitness.empty))) } ?: listOf()
        val localTxIn = tx.localInputs.sortedBy { i -> i.serialId }.zip(localSigs.witnesses).map { (i, w) -> Pair(i.serialId, TxIn(OutPoint(i.previousTx, i.previousTxOutput), ByteVector.empty, i.sequence.toLong(), w)) }
        val remoteTxIn = tx.remoteInputs.sortedBy { i -> i.serialId }.zip(remoteSigs.witnesses).map { (i, w) -> Pair(i.serialId, TxIn(i.outPoint, ByteVector.empty, i.sequence.toLong(), w)) }
        val inputs = (sharedTxIn + localTxIn + remoteTxIn).sortedBy { (serialId, _) -> serialId }.map { (_, i) -> i }
        val sharedTxOut = listOf(Pair(tx.sharedOutput.serialId, TxOut(tx.sharedOutput.amount, tx.sharedOutput.pubkeyScript)))
        val localTxOut = tx.localOutputs.map { o -> Pair(o.serialId, TxOut(o.amount, o.pubkeyScript)) }
        val remoteTxOut = tx.remoteOutputs.map { o -> Pair(o.serialId, TxOut(o.amount, o.pubkeyScript)) }
        val outputs = (sharedTxOut + localTxOut + remoteTxOut).sortedBy { (serialId, _) -> serialId }.map { (_, o) -> o }
        Transaction(2, inputs, outputs, tx.lockTime)
    }
    override val txId: ByteVector32 = signedTx.txid
    val feerate: FeeratePerKw = Transactions.fee2rate(tx.fees, signedTx.weight())
}

sealed class InteractiveTxSessionAction {
    // @formatter:off
    data class SendMessage(val msg: InteractiveTxConstructionMessage) : InteractiveTxSessionAction()
    data class SignSharedTx(val sharedTx: SharedTransaction, val sharedOutputIndex: Int, val txComplete: TxComplete?) : InteractiveTxSessionAction()
    sealed class RemoteFailure : InteractiveTxSessionAction()
    data class InvalidSerialId(val channelId: ByteVector32, val serialId: Long) : RemoteFailure() { override fun toString(): String = "invalid serial_id=$serialId" }
    data class UnknownSerialId(val channelId: ByteVector32, val serialId: Long) : RemoteFailure() { override fun toString(): String = "unknown serial_id=$serialId" }
    data class TooManyInteractiveTxRounds(val channelId: ByteVector32) : RemoteFailure() { override fun toString(): String = "too many messages exchanged during interactive tx construction" }
    data class DuplicateSerialId(val channelId: ByteVector32, val serialId: Long) : RemoteFailure() { override fun toString(): String = "duplicate serial_id=$serialId" }
    data class DuplicateInput(val channelId: ByteVector32, val serialId: Long, val previousTxId: ByteVector32, val previousTxOutput: Long) : RemoteFailure() { override fun toString(): String = "duplicate input $previousTxId:$previousTxOutput (serial_id=$serialId)" }
    data class InputOutOfBounds(val channelId: ByteVector32, val serialId: Long, val previousTxId: ByteVector32, val previousTxOutput: Long) : RemoteFailure() { override fun toString(): String = "invalid input $previousTxId:$previousTxOutput (serial_id=$serialId)" }
    data class NonReplaceableInput(val channelId: ByteVector32, val serialId: Long, val previousTxId: ByteVector32, val previousTxOutput: Long, val sequence: Long) : RemoteFailure() { override fun toString(): String = "$previousTxId:$previousTxOutput is not replaceable (serial_id=$serialId, nSequence=$sequence)" }
    data class NonSegwitInput(val channelId: ByteVector32, val serialId: Long, val previousTxId: ByteVector32, val previousTxOutput: Long) : RemoteFailure() { override fun toString(): String = "$previousTxId:$previousTxOutput is not a native segwit input (serial_id=$serialId)" }
    data class PreviousTxMissing(val channelId: ByteVector32, val serialId: Long) : RemoteFailure() { override fun toString(): String = "previous tx missing from tx_add_input (serial_id=$serialId)" }
    data class InvalidSharedInput(val channelId: ByteVector32, val serialId: Long) : RemoteFailure() { override fun toString(): String = "invalid shared tx_add_input (serial_id=$serialId)" }
    data class OutputBelowDust(val channelId: ByteVector32, val serialId: Long, val amount: Satoshi, val dustLimit: Satoshi) : RemoteFailure() { override fun toString(): String = "invalid output amount=$amount below dust=$dustLimit (serial_id=$serialId)" }
    data class InvalidTxInputOutputCount(val channelId: ByteVector32, val inputCount: Int, val outputCount: Int) : RemoteFailure() { override fun toString(): String = "invalid number of inputs or outputs (inputCount=$inputCount, outputCount=$outputCount)" }
    data class InvalidTxBelowReserve(val channelId: ByteVector32, val remoteAmount: Satoshi, val reserve: Satoshi) : RemoteFailure() { override fun toString(): String = "peer takes too much funds out and falls below reverse ($remoteAmount < $reserve)" }
    data class InvalidTxSharedInput(val channelId: ByteVector32) : RemoteFailure() { override fun toString(): String = "shared input is missing or duplicated" }
    data class InvalidTxSharedOutput(val channelId: ByteVector32) : RemoteFailure() { override fun toString(): String = "shared output is missing or duplicated" }
    data class InvalidTxSharedAmount(val channelId: ByteVector32, val serialId: Long, val amount: Satoshi, val expected: Satoshi) : RemoteFailure() { override fun toString(): String = "invalid shared output amount=$amount expected=$expected (serial_id=$serialId)" }
    data class InvalidTxChangeAmount(val channelId: ByteVector32, val txId: ByteVector32) : RemoteFailure() { override fun toString(): String = "change amount is too high (txId=$txId)" }
    data class InvalidTxWeight(val channelId: ByteVector32, val txId: ByteVector32) : RemoteFailure() { override fun toString(): String = "transaction weight is too big for standardness rules (txId=$txId)" }
    data class InvalidTxFeerate(val channelId: ByteVector32, val txId: ByteVector32, val targetFeerate: FeeratePerKw, val actualFeerate: FeeratePerKw) : RemoteFailure() { override fun toString(): String = "transaction feerate too low (txId=$txId, targetFeerate=$targetFeerate, actualFeerate=$actualFeerate" }
    data class InvalidTxDoesNotDoubleSpendPreviousTx(val channelId: ByteVector32, val txId: ByteVector32, val previousTxId: ByteVector32) : RemoteFailure() { override fun toString(): String = "transaction replacement with txId=$txId doesn't double-spend previous attempt (txId=$previousTxId)" }
    // @formatter:on
}

data class InteractiveTxSession(
    val fundingParams: InteractiveTxParams,
    val previousLocalBalance: Satoshi,
    val previousRemoteBalance: Satoshi,
    val toSend: List<Either<InteractiveTxInput.Outgoing, InteractiveTxOutput.Outgoing>>,
    val previousTxs: List<SignedSharedTransaction> = listOf(),
    val localInputs: List<InteractiveTxInput.Outgoing> = listOf(),
    val remoteInputs: List<InteractiveTxInput.Incoming> = listOf(),
    val localOutputs: List<InteractiveTxOutput.Outgoing> = listOf(),
    val remoteOutputs: List<InteractiveTxOutput.Incoming> = listOf(),
    val txCompleteSent: Boolean = false,
    val txCompleteReceived: Boolean = false,
    val inputsReceivedCount: Int = 0,
    val outputsReceivedCount: Int = 0,
) {
    constructor(fundingParams: InteractiveTxParams, previousLocalBalance: Satoshi, previousRemoteBalance: Satoshi, fundingContributions: FundingContributions, previousTxs: List<SignedSharedTransaction> = listOf()) : this(
        fundingParams,
        previousLocalBalance,
        previousRemoteBalance,
        fundingContributions.inputs.map { i -> Either.Left<InteractiveTxInput.Outgoing, InteractiveTxOutput.Outgoing>(i) } + fundingContributions.outputs.map { o -> Either.Right<InteractiveTxInput.Outgoing, InteractiveTxOutput.Outgoing>(o) },
        previousTxs
    )

    val isComplete: Boolean = txCompleteSent && txCompleteReceived

    fun send(): Pair<InteractiveTxSession, InteractiveTxSessionAction> {
        return when (val msg = toSend.firstOrNull()) {
            null -> {
                val txComplete = TxComplete(fundingParams.channelId)
                val next = copy(txCompleteSent = true)
                if (next.isComplete) {
                    Pair(next, next.validateTx(txComplete))
                } else {
                    Pair(next, InteractiveTxSessionAction.SendMessage(txComplete))
                }
            }
            is Either.Left -> {
                val next = copy(toSend = toSend.tail(), localInputs = localInputs + msg.value, txCompleteSent = false)
                val txAddInput = when (msg.value) {
                    is InteractiveTxInput.Local -> TxAddInput(fundingParams.channelId, msg.value.serialId, msg.value.previousTx, msg.value.previousTxOutput, msg.value.sequence)
                    is InteractiveTxInput.Shared -> TxAddInput(fundingParams.channelId, msg.value.serialId, msg.value.outPoint, msg.value.sequence)
                }
                Pair(next, InteractiveTxSessionAction.SendMessage(txAddInput))
            }
            is Either.Right -> {
                val next = copy(toSend = toSend.tail(), localOutputs = localOutputs + msg.value, txCompleteSent = false)
                val txAddOutput = when (msg.value) {
                    is InteractiveTxOutput.Local -> TxAddOutput(fundingParams.channelId, msg.value.serialId, msg.value.amount, msg.value.pubkeyScript)
                    is InteractiveTxOutput.Shared -> TxAddOutput(fundingParams.channelId, msg.value.serialId, msg.value.amount, msg.value.pubkeyScript)
                }
                Pair(next, InteractiveTxSessionAction.SendMessage(txAddOutput))
            }
        }
    }

    private fun receiveInput(message: TxAddInput): Either<InteractiveTxSessionAction.RemoteFailure, InteractiveTxInput.Incoming> {
        if (inputsReceivedCount + 1 >= MAX_INPUTS_OUTPUTS_RECEIVED) {
            return Either.Left(InteractiveTxSessionAction.TooManyInteractiveTxRounds(message.channelId))
        }
        if (remoteInputs.find { i -> (i as InteractiveTxInput).serialId == message.serialId } != null) {
            return Either.Left(InteractiveTxSessionAction.DuplicateSerialId(message.channelId, message.serialId))
        }
        // We check whether this is the shared input or a remote input.
        val input = when (message.previousTx) {
            null -> {
                val expectedSharedOutpoint = fundingParams.sharedInput?.info?.outPoint ?: return Either.Left(InteractiveTxSessionAction.PreviousTxMissing(message.channelId, message.serialId))
                val receivedSharedOutpoint = message.sharedInput ?: return Either.Left(InteractiveTxSessionAction.PreviousTxMissing(message.channelId, message.serialId))
                if (expectedSharedOutpoint != receivedSharedOutpoint) return Either.Left(InteractiveTxSessionAction.PreviousTxMissing(message.channelId, message.serialId))
                InteractiveTxInput.Shared(message.serialId, receivedSharedOutpoint, message.sequence, previousLocalBalance, previousRemoteBalance)
            }
            else -> {
                if (message.previousTx.txOut.size <= message.previousTxOutput) {
                    return Either.Left(InteractiveTxSessionAction.InputOutOfBounds(message.channelId, message.serialId, message.previousTx.txid, message.previousTxOutput))
                }
                fundingParams.sharedInput?.let {
                    if (it.info.outPoint == OutPoint(message.previousTx, message.previousTxOutput)) {
                        return Either.Left(InteractiveTxSessionAction.InvalidSharedInput(message.channelId, message.serialId))
                    }
                }
                if (!Script.isNativeWitnessScript(message.previousTx.txOut[message.previousTxOutput.toInt()].publicKeyScript)) {
                    return Either.Left(InteractiveTxSessionAction.NonSegwitInput(message.channelId, message.serialId, message.previousTx.txid, message.previousTxOutput))
                }
                InteractiveTxInput.Remote(message.serialId, OutPoint(message.previousTx, message.previousTxOutput), message.previousTx.txOut[message.previousTxOutput.toInt()], message.sequence)
            }
        }
        if ((localInputs.map { (it as InteractiveTxInput).outPoint } + remoteInputs.map { (it as InteractiveTxInput).outPoint }).contains(input.outPoint)) {
            return Either.Left(InteractiveTxSessionAction.DuplicateInput(message.channelId, message.serialId, input.outPoint.txid, input.outPoint.index))
        }
        if (message.sequence > 0xfffffffdU) {
            return Either.Left(InteractiveTxSessionAction.NonReplaceableInput(message.channelId, message.serialId, input.outPoint.txid, input.outPoint.index, message.sequence.toLong()))
        }
        return Either.Right(input)
    }

    private fun receiveOutput(message: TxAddOutput): Either<InteractiveTxSessionAction.RemoteFailure, InteractiveTxOutput.Incoming> {
        return if (outputsReceivedCount + 1 >= MAX_INPUTS_OUTPUTS_RECEIVED) {
            Either.Left(InteractiveTxSessionAction.TooManyInteractiveTxRounds(message.channelId))
        } else if (remoteOutputs.find { o -> (o as InteractiveTxOutput).serialId == message.serialId } != null) {
            Either.Left(InteractiveTxSessionAction.DuplicateSerialId(message.channelId, message.serialId))
        } else if (message.amount < fundingParams.dustLimit) {
            Either.Left(InteractiveTxSessionAction.OutputBelowDust(message.channelId, message.serialId, message.amount, fundingParams.dustLimit))
        } else if (message.pubkeyScript == fundingParams.fundingPubkeyScript && message.amount != fundingParams.fundingAmount) {
            Either.Left(InteractiveTxSessionAction.InvalidTxSharedAmount(message.channelId, message.serialId, message.amount, fundingParams.fundingAmount))
        } else if (message.pubkeyScript == fundingParams.fundingPubkeyScript) {
            Either.Right(InteractiveTxOutput.Shared(message.serialId, message.pubkeyScript, fundingParams.localAmount, fundingParams.remoteAmount))
        } else {
            Either.Right(InteractiveTxOutput.Remote(message.serialId, message.amount, message.pubkeyScript))
        }
    }

    fun receive(message: InteractiveTxConstructionMessage): Pair<InteractiveTxSession, InteractiveTxSessionAction> {
        if (message is HasSerialId && (message.serialId.mod(2) == 1) != fundingParams.isInitiator) {
            return Pair(this, InteractiveTxSessionAction.InvalidSerialId(fundingParams.channelId, message.serialId))
        }
        return when (message) {
            is TxAddInput -> {
                receiveInput(message).fold(
                    { f -> Pair(this, f) },
                    { input -> copy(remoteInputs = remoteInputs + input, inputsReceivedCount = inputsReceivedCount + 1, txCompleteReceived = false).send() }
                )
            }
            is TxAddOutput -> {
                receiveOutput(message).fold(
                    { f -> Pair(this, f) },
                    { output -> copy(remoteOutputs = remoteOutputs + output, outputsReceivedCount = outputsReceivedCount + 1, txCompleteReceived = false).send() }
                )
            }
            is TxRemoveInput -> {
                val remoteInputs1 = remoteInputs.filterNot { i -> (i as InteractiveTxInput).serialId == message.serialId }
                if (remoteInputs.size != remoteInputs1.size) {
                    val next = copy(remoteInputs = remoteInputs1, txCompleteReceived = false)
                    next.send()
                } else {
                    Pair(this, InteractiveTxSessionAction.UnknownSerialId(message.channelId, message.serialId))
                }
            }
            is TxRemoveOutput -> {
                val remoteOutputs1 = remoteOutputs.filterNot { o -> (o as InteractiveTxOutput).serialId == message.serialId }
                if (remoteOutputs.size != remoteOutputs1.size) {
                    val next = copy(remoteOutputs = remoteOutputs1, txCompleteReceived = false)
                    next.send()
                } else {
                    Pair(this, InteractiveTxSessionAction.UnknownSerialId(message.channelId, message.serialId))
                }
            }
            is TxComplete -> {
                val next = copy(txCompleteReceived = true)
                if (next.isComplete) {
                    Pair(next, next.validateTx(null))
                } else {
                    next.send()
                }
            }
        }
    }

    private fun validateTx(txComplete: TxComplete?): InteractiveTxSessionAction {
        if (localInputs.size + remoteInputs.size > 252 || localOutputs.size + remoteOutputs.size > 252) {
            return InteractiveTxSessionAction.InvalidTxInputOutputCount(fundingParams.channelId, localInputs.size + remoteInputs.size, localOutputs.size + remoteOutputs.size)
        }

        val sharedInputs = localInputs.filterIsInstance<InteractiveTxInput.Shared>() + remoteInputs.filterIsInstance<InteractiveTxInput.Shared>()
        val localOnlyInputs = localInputs.filterIsInstance<InteractiveTxInput.Local>()
        val remoteOnlyInputs = remoteInputs.filterIsInstance<InteractiveTxInput.Remote>()
        val sharedOutputs = localOutputs.filterIsInstance<InteractiveTxOutput.Shared>() + remoteOutputs.filterIsInstance<InteractiveTxOutput.Shared>()
        val localOnlyOutputs = localOutputs.filterIsInstance<InteractiveTxOutput.Local>()
        val remoteOnlyOutputs = remoteOutputs.filterIsInstance<InteractiveTxOutput.Remote>()

        val sharedInput = fundingParams.sharedInput?.let {
            val remoteReserve = (fundingParams.fundingAmount / 100).max(fundingParams.dustLimit)
            if (fundingParams.remoteAmount < remoteReserve && remoteOnlyOutputs.isNotEmpty()) {
                return InteractiveTxSessionAction.InvalidTxBelowReserve(fundingParams.channelId, fundingParams.remoteAmount, remoteReserve)
            }
            if (sharedInputs.size != 1) {
                return InteractiveTxSessionAction.InvalidTxSharedInput(fundingParams.channelId)
            }
            sharedInputs.first()
        }

        if (sharedOutputs.size != 1) {
            return InteractiveTxSessionAction.InvalidTxSharedOutput(fundingParams.channelId)
        }
        val sharedOutput = sharedOutputs.first()

        val sharedTx = SharedTransaction(sharedInput, sharedOutput, localOnlyInputs, remoteOnlyInputs, localOnlyOutputs, remoteOnlyOutputs, fundingParams.lockTime)
        val tx = sharedTx.buildUnsignedTx()
        val sharedOutputIndex = tx.txOut.indexOfFirst { it.publicKeyScript == fundingParams.fundingPubkeyScript }

        if (sharedTx.localAmountIn < sharedTx.localAmountOut || sharedTx.remoteAmountIn < sharedTx.remoteAmountOut) {
            return InteractiveTxSessionAction.InvalidTxChangeAmount(fundingParams.channelId, tx.txid)
        }

        // The transaction isn't signed yet, and segwit witnesses can be arbitrarily low (e.g. when using an OP_1 script),
        // so we use empty witnesses to provide a lower bound on the transaction weight.
        if (tx.weight() > Transactions.MAX_STANDARD_TX_WEIGHT) {
            return InteractiveTxSessionAction.InvalidTxWeight(fundingParams.channelId, tx.txid)
        }

        if (previousTxs.isNotEmpty()) {
            // This is an RBF attempt: even if our peer does not contribute to the feerate increase, we'd like to broadcast
            // the new transaction if it has a better feerate than the previous one. This is better than being stuck with
            // a transaction that doesn't confirm.
            // We don't know yet the witness weight since the transaction isn't signed, so we compare unsigned transactions.
            val previousUnsignedTx = previousTxs.first().tx.buildUnsignedTx()
            val previousFeerate = Transactions.fee2rate(previousTxs.first().tx.fees, previousUnsignedTx.weight())
            val nextFeerate = Transactions.fee2rate(sharedTx.fees, tx.weight())
            if (nextFeerate <= previousFeerate) {
                return InteractiveTxSessionAction.InvalidTxFeerate(fundingParams.channelId, tx.txid, fundingParams.targetFeerate, nextFeerate)
            }
        } else {
            val minimumFee = Transactions.weight2fee(fundingParams.targetFeerate, tx.weight())
            if (sharedTx.fees < minimumFee) {
                return InteractiveTxSessionAction.InvalidTxFeerate(fundingParams.channelId, tx.txid, fundingParams.targetFeerate, Transactions.fee2rate(sharedTx.fees, tx.weight()))
            }
        }

        // The transaction must double-spend every previous attempt, otherwise there is a risk that two funding transactions
        // confirm for the same channel.
        val currentInputs = tx.txIn.map { i -> i.outPoint }.toSet()
        previousTxs.forEach { previousSharedTx ->
            val previousTx = previousSharedTx.tx.buildUnsignedTx()
            val previousInputs = previousTx.txIn.map { i -> i.outPoint }
            if (previousInputs.find { i -> currentInputs.contains(i) } == null) {
                return InteractiveTxSessionAction.InvalidTxDoesNotDoubleSpendPreviousTx(fundingParams.channelId, tx.txid, previousTx.txid)
            }
        }

        return InteractiveTxSessionAction.SignSharedTx(sharedTx, sharedOutputIndex, txComplete)
    }

    companion object {
        // We restrict the number of inputs / outputs that our peer can send us to ensure the protocol eventually ends.
        const val MAX_INPUTS_OUTPUTS_RECEIVED = 4096
    }
}
