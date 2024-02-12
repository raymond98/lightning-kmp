package fr.acinq.lightning.blockchain.electrum

import fr.acinq.bitcoin.MnemonicCode
import fr.acinq.lightning.NodeParams
import fr.acinq.lightning.crypto.LocalKeyManager
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.utils.toByteVector
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

class SwapInWalletTestsCommon : LightningTestSuite() {

    @Test
    fun `swap-in wallet test`() = runSuspendTest(timeout = 15000.seconds) {
        val mnemonics = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" ")
        val keyManager = LocalKeyManager(MnemonicCode.toSeed(mnemonics, "").toByteVector(), NodeParams.Chain.Testnet, TestConstants.aliceSwapInServerXpub)
        val client = connectToTestnetServer()
        val wallet = SwapInWallet(NodeParams.Chain.Testnet, keyManager.swapInOnChainWallet, client, addressGenerationWindow = 3, this, loggerFactory)

        // addresses 0 to 5 have funds on them, the current address is the 6th
        assertEquals(6, wallet.swapInAddressFlow.filterNotNull().map {
            println(it)
            it
        }.first().second)
    }
}