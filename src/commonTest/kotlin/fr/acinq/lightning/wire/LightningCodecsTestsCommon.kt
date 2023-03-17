package fr.acinq.lightning.wire

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Features
import fr.acinq.lightning.Lightning.randomBytes
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomBytes64
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.ChannelType
import fr.acinq.lightning.channel.Origin
import fr.acinq.lightning.crypto.assertArrayEquals
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.*

class LightningCodecsTestsCommon : LightningTestSuite() {

    private fun point(fill: Byte) = PrivateKey(ByteArray(32) { fill }).publicKey()

    fun publicKey(fill: Byte) = point(fill)

    @Test
    fun `encode - decode uint64`() {
        val testCases = mapOf(
            0UL to Hex.decode("00 00 00 00 00 00 00 00"),
            42UL to Hex.decode("00 00 00 00 00 00 00 2a"),
            6211610197754262546UL to Hex.decode("56 34 12 90 78 56 34 12"),
            17293822569102704638UL to Hex.decode("ef ff ff ff ff ff ff fe"),
            17293822569102704639UL to Hex.decode("ef ff ff ff ff ff ff ff"),
            18446744073709551614UL to Hex.decode("ff ff ff ff ff ff ff fe"),
            18446744073709551615UL to Hex.decode("ff ff ff ff ff ff ff ff")
        )

        testCases.forEach {
            val out = ByteArrayOutput()
            LightningCodecs.writeU64(it.key.toLong(), out)
            assertArrayEquals(it.value, out.toByteArray())
            val decoded = LightningCodecs.u64(ByteArrayInput(it.value))
            assertEquals(it.key, decoded.toULong())
        }
    }

    @Test
    fun `bigsize serialization`() {
        val raw = """[
    {
        "name": "zero",
        "value": 0,
        "bytes": "00"
    },
    {
        "name": "one byte value",
        "value": 42,
        "bytes": "2a"
    },
    {
        "name": "one byte high",
        "value": 252,
        "bytes": "fc"
    },
    {
        "name": "two byte low",
        "value": 253,
        "bytes": "fd00fd"
    },
    {
        "name": "two byte value",
        "value": 255,
        "bytes": "fd00ff"
    },
    {
        "name": "two byte value",
        "value": 550,
        "bytes": "fd0226"
    },
    {
        "name": "two byte high",
        "value": 65535,
        "bytes": "fdffff"
    },
    {
        "name": "four byte low",
        "value": 65536,
        "bytes": "fe00010000"
    },
    {
        "name": "four byte value",
        "value": 998000,
        "bytes": "fe000f3a70"
    },
    {
        "name": "four byte high",
        "value": 4294967295,
        "bytes": "feffffffff"
    },
    {
        "name": "eight byte low",
        "value": 4294967296,
        "bytes": "ff0000000100000000"
    },
    {
        "name": "eight byte high",
        "value": 18446744073709551615,
        "bytes": "ffffffffffffffffff"
    },
    {
        "name": "two byte not canonical",
        "value": 0,
        "bytes": "fd00fc",
        "exp_error": "decoded bigsize is not canonical"
    },
    {
        "name": "four byte not canonical",
        "value": 0,
        "bytes": "fe0000ffff",
        "exp_error": "decoded bigsize is not canonical"
    },
    {
        "name": "eight byte not canonical",
        "value": 0,
        "bytes": "ff00000000ffffffff",
        "exp_error": "decoded bigsize is not canonical"
    },
    {
        "name": "two byte short read",
        "value": 0,
        "bytes": "fd00",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "four byte short read",
        "value": 0,
        "bytes": "feffff",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "eight byte short read",
        "value": 0,
        "bytes": "ffffffffff",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "one byte no read",
        "value": 0,
        "bytes": "",
        "exp_error": "EOF"
    },
    {
        "name": "two byte no read",
        "value": 0,
        "bytes": "fd",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "four byte no read",
        "value": 0,
        "bytes": "fe",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "eight byte no read",
        "value": 0,
        "bytes": "ff",
        "exp_error": "unexpected EOF"
    }
]"""

        val items = Json.parseToJsonElement(raw)
        items.jsonArray.forEach {
            val name = it.jsonObject["name"]?.jsonPrimitive?.content!!
            val bytes = Hex.decode(it.jsonObject["bytes"]?.jsonPrimitive?.content!!)
            val value = it.jsonObject["value"]?.jsonPrimitive?.content?.toULong()!!
            if (it.jsonObject["exp_error"] != null) {
                assertFails(name) { LightningCodecs.bigSize(ByteArrayInput(bytes)) }
            } else {
                assertEquals(value, LightningCodecs.bigSize(ByteArrayInput(bytes)).toULong(), name)
                val out = ByteArrayOutput()
                LightningCodecs.writeBigSize(value.toLong(), out)
                assertArrayEquals(bytes, out.toByteArray())
            }
        }
    }

    @Test
    fun `encode - decode init message`() {
        data class TestCase(val encoded: ByteVector, val rawFeatures: ByteVector, val networks: List<ByteVector32>, val valid: Boolean, val reEncoded: ByteVector? = null)

        val chainHash1 = ByteVector32.fromValidHex("0101010101010101010101010101010101010101010101010101010101010101")
        val chainHash2 = ByteVector32.fromValidHex("0202020202020202020202020202020202020202020202020202020202020202")

        val testCases = listOf(
            TestCase(ByteVector("0000 0000"), ByteVector(""), listOf(), true), // no features
            TestCase(ByteVector("0000 0002088a"), ByteVector("088a"), listOf(), true), // no global features
            TestCase(ByteVector("00020200 0000"), ByteVector("0200"), listOf(), true, ByteVector("0000 00020200")), // no local features
            TestCase(ByteVector("00020200 0002088a"), ByteVector("0a8a"), listOf(), true, ByteVector("0000 00020a8a")), // local and global - no conflict - same size
            TestCase(ByteVector("00020200 0003020002"), ByteVector("020202"), listOf(), true, ByteVector("0000 0003020202")), // local and global - no conflict - different sizes
            TestCase(ByteVector("00020a02 0002088a"), ByteVector("0a8a"), listOf(), true, ByteVector("0000 00020a8a")), // local and global - conflict - same size
            TestCase(ByteVector("00022200 000302aaa2"), ByteVector("02aaa2"), listOf(), true, ByteVector("0000 000302aaa2")), // local and global - conflict - different sizes
            TestCase(ByteVector("0000 0002088a 03012a05022aa2"), ByteVector("088a"), listOf(), true), // unknown odd records
            TestCase(ByteVector("0000 0002088a 03012a04022aa2"), ByteVector("088a"), listOf(), false), // unknown even records
            TestCase(ByteVector("0000 0002088a 0120010101010101010101010101010101010101010101010101010101010101"), ByteVector("088a"), listOf(), false), // invalid tlv stream
            TestCase(ByteVector("0000 0002088a 01200101010101010101010101010101010101010101010101010101010101010101"), ByteVector("088a"), listOf(chainHash1), true), // single network
            TestCase(
                ByteVector("0000 0002088a 014001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202"),
                ByteVector("088a"),
                listOf(chainHash1, chainHash2),
                true
            ), // multiple networks
            TestCase(ByteVector("0000 0002088a 0120010101010101010101010101010101010101010101010101010101010101010103012a"), ByteVector("088a"), listOf(chainHash1), true), // network and unknown odd records
            TestCase(ByteVector("0000 0002088a 0120010101010101010101010101010101010101010101010101010101010101010102012a"), ByteVector("088a"), listOf(), false) // network and unknown even records
        )

        for (testCase in testCases) {
            val result = kotlin.runCatching {
                val init = Init.read(testCase.encoded.toByteArray())
                assertEquals(testCase.rawFeatures, init.features)
                assertEquals(testCase.networks, init.networks)
                val encoded = init.write()
                assertEquals(testCase.reEncoded ?: testCase.encoded, ByteVector(encoded), testCase.toString())
            }
            assertEquals(result.isFailure, !testCase.valid, testCase.toString())
        }
    }

    @Test
    fun `encode - decode warning message`() {
        val testCases = mapOf(
            Warning("") to ByteVector("000100000000000000000000000000000000000000000000000000000000000000000000"),
            Warning("connection-level issue") to ByteVector("000100000000000000000000000000000000000000000000000000000000000000000016636f6e6e656374696f6e2d6c6576656c206973737565"),
            Warning(ByteVector32.One, "") to ByteVector("000101000000000000000000000000000000000000000000000000000000000000000000"),
            Warning(ByteVector32.One, "channel-specific issue") to ByteVector("0001010000000000000000000000000000000000000000000000000000000000000000166368616e6e656c2d7370656369666963206973737565"),
        )

        testCases.forEach {
            val decoded = LightningMessage.decode(it.value.toByteArray())
            assertNotNull(decoded)
            assertEquals(it.key, decoded)
            val reEncoded = LightningMessage.encode(decoded)
            assertEquals(it.value, ByteVector(reEncoded))
        }
    }

    @Test
    fun `decode invalid open_channel`() {
        val defaultEncoded = ByteVector(
            "0000000000000000000000000000000000000000000000000000000000000000 0100000000000000000000000000000000000000000000000000000000000000 00001388 00000fa0 000000000003d090 00000000000001f4 000000000000c350 000000000000000f 0090 01e3 0009eb10 031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f 024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766 02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337 03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b 0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7 03f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a 01"
        )
        val testCases = listOf(
            defaultEncoded + ByteVector("00"), // truncated length
            defaultEncoded + ByteVector("01"), // truncated length
            defaultEncoded + ByteVector("0004 123456"), // truncated upfront_shutdown_script
            defaultEncoded + ByteVector("0000 2a012a"), // invalid tlv stream (unknown even record)
            defaultEncoded + ByteVector("0000 01012a 030201"), // invalid tlv stream (truncated)
            defaultEncoded + ByteVector("2a012a"), // invalid tlv stream (unknown even record)
            defaultEncoded + ByteVector("01012a 030201") // invalid tlv stream (truncated)
        )
        testCases.forEach {
            assertFails { OpenDualFundedChannel.read(it.toByteArray()) }
        }
    }

    @Test
    fun `encode - decode open_channel`() {
        // @formatter:off
        val defaultOpen = OpenDualFundedChannel(ByteVector32.Zeroes, ByteVector32.One, FeeratePerKw(5000.sat), FeeratePerKw(4000.sat), 250_000.sat, 500.sat, 50_000, 15.msat, CltvExpiryDelta(144), 483, 650_000, publicKey(1), publicKey(2), publicKey(3), publicKey(4), publicKey(5), publicKey(6), publicKey(7), 1.toByte())
        val defaultEncoded = ByteVector("0040 0000000000000000000000000000000000000000000000000000000000000000 0100000000000000000000000000000000000000000000000000000000000000 00001388 00000fa0 000000000003d090 00000000000001f4 000000000000c350 000000000000000f 0090 01e3 0009eb10 031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f 024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766 02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337 03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b 0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7 03f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a 02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f 01")
        val testCases = listOf(
            defaultOpen to defaultEncoded,
            defaultOpen.copy(tlvStream = TlvStream(listOf(ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.AnchorOutputs)))) to (defaultEncoded + ByteVector("0103101000")),
            defaultOpen.copy(tlvStream = TlvStream(listOf(ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.AnchorOutputs), ChannelTlv.PushAmountTlv(25_000.msat)))) to (defaultEncoded + ByteVector("0103101000 fe470000070261a8")),
            defaultOpen.copy(tlvStream = TlvStream(listOf(ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.AnchorOutputs), ChannelTlv.RequireConfirmedInputsTlv))) to (defaultEncoded + ByteVector("0103101000 0200")),
            defaultOpen.copy(tlvStream = TlvStream(listOf(ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.AnchorOutputs)), listOf(GenericTlv(321, ByteVector("2a2a")), GenericTlv(325, ByteVector("02"))))) to (defaultEncoded + ByteVector("0103101000 fd0141022a2a fd01450102")),
            defaultOpen.copy(tlvStream = TlvStream(listOf(ChannelTlv.OriginTlv(Origin.PayToOpenOrigin(ByteVector32.fromValidHex("187bf923f7f11ef732b73c417eb5a57cd4667b20a6f130ff505cd7ad3ab87281"), 1234.sat, 1_111_000.msat))))) to (defaultEncoded + ByteVector("fe47000005 32 0001 187bf923f7f11ef732b73c417eb5a57cd4667b20a6f130ff505cd7ad3ab87281 00000000000004d2 000000000010f3d8")),
            defaultOpen.copy(tlvStream = TlvStream(listOf(ChannelTlv.OriginTlv(Origin.PleaseOpenChannelOrigin(ByteVector32("2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25"), 1_234_567.msat, 321.sat, 1_111_000.msat))))) to (defaultEncoded + ByteVector("fe47000005 3a 0004 2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25 000000000012d687 0000000000000141 000000000010f3d8")),
        )
        // @formatter:on
        testCases.forEach { (open, bin) ->
            val decoded = LightningMessage.decode(bin.toByteArray())
            assertNotNull(decoded)
            assertEquals(decoded, open)
            val encoded = LightningMessage.encode(open)
            assertEquals(encoded.byteVector(), bin)
        }
    }

    @Test
    fun `encode - decode accept_channel`() {
        // @formatter:off
        val defaultAccept = AcceptDualFundedChannel(ByteVector32.One, 50_000.sat, 473.sat, 100_000_000, 1.msat, 6, CltvExpiryDelta(144), 50, publicKey(1), point(2), point(3), point(4), point(5), point(6), publicKey(7))
        val defaultEncoded = ByteVector("0041 0100000000000000000000000000000000000000000000000000000000000000 000000000000c350 00000000000001d9 0000000005f5e100 0000000000000001 00000006 0090 0032 031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f 024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766 02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337 03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b 0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7 03f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a 02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f")
        val testCases = listOf(
            defaultAccept to defaultEncoded,
            defaultAccept.copy(tlvStream = TlvStream(listOf(ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.StaticRemoteKey)))) to (defaultEncoded + ByteVector("01021000")),
            defaultAccept.copy(tlvStream = TlvStream(listOf(ChannelTlv.UpfrontShutdownScriptTlv(ByteVector("01abcdef")), ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.AnchorOutputs)))) to (defaultEncoded + ByteVector("000401abcdef 0103101000")),
            defaultAccept.copy(tlvStream = TlvStream(listOf(ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.AnchorOutputs), ChannelTlv.PushAmountTlv(1729.msat)))) to (defaultEncoded + ByteVector("0103101000 fe470000070206c1")),
            defaultAccept.copy(tlvStream = TlvStream(listOf(ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.AnchorOutputs), ChannelTlv.RequireConfirmedInputsTlv))) to (defaultEncoded + ByteVector("0103101000 0200")),
            defaultAccept.copy(tlvStream = TlvStream(listOf(ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.AnchorOutputs)), listOf(GenericTlv(113, ByteVector("deadbeef"))))) to (defaultEncoded + ByteVector("0103101000 7104deadbeef")),
        )
        // @formatter:on
        testCases.forEach { (accept, bin) ->
            val decoded = LightningMessage.decode(bin.toByteArray())
            assertNotNull(decoded)
            assertEquals(decoded, accept)
            val encoded = LightningMessage.encode(accept)
            assertEquals(encoded.byteVector(), bin)
        }
    }

    @Test
    fun `encode - decode channel_ready`() {
        val testCases = listOf(
            // @formatter:off
            ChannelReady(ByteVector32("02094a1009491c4aa4320ce4400bbb556399b720a35b0922b73316bfeb49e118"), PublicKey.fromHex("02df89f6e2a2c3e7dfd536c4b65add892026c032e6ec818347e0e44b4ab2fcadca")) to "002402094a1009491c4aa4320ce4400bbb556399b720a35b0922b73316bfeb49e11802df89f6e2a2c3e7dfd536c4b65add892026c032e6ec818347e0e44b4ab2fcadca",
            ChannelReady(ByteVector32("02094a1009491c4aa4320ce4400bbb556399b720a35b0922b73316bfeb49e118"), PublicKey.fromHex("02df89f6e2a2c3e7dfd536c4b65add892026c032e6ec818347e0e44b4ab2fcadca"), TlvStream(listOf(ChannelReadyTlv.ShortChannelIdTlv(ShortChannelId(1729))))) to "002402094a1009491c4aa4320ce4400bbb556399b720a35b0922b73316bfeb49e11802df89f6e2a2c3e7dfd536c4b65add892026c032e6ec818347e0e44b4ab2fcadca010800000000000006c1",
            // @formatter:on
        )
        testCases.forEach { (channelReady, bin) ->
            val decoded = LightningMessage.decode(Hex.decode(bin))
            assertEquals(decoded, channelReady)
            val encoded = LightningMessage.encode(channelReady)
            assertEquals(Hex.encode(encoded), bin)
        }
    }

    @Test
    fun `encode - decode interactive-tx messages`() {
        val channelId1 = ByteVector32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        val channelId2 = ByteVector32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        val signature = ByteVector64("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        // This is a random mainnet transaction.
        val tx1 = Transaction.read(
            "020000000001014ade359c5deb7c1cde2e94f401854658f97d7fa31c17ce9a831db253120a0a410100000017160014eb9a5bd79194a23d19d6ec473c768fb74f9ed32cffffffff021ca408000000000017a914946118f24bb7b37d5e9e39579e4a411e70f5b6a08763e703000000000017a9143638b2602d11f934c04abc6adb1494f69d1f14af8702473044022059ddd943b399211e4266a349f26b3289979e29f9b067792c6cfa8cc5ae25f44602204d627a5a5b603d0562e7969011fb3d64908af90a3ec7c876eaa9baf61e1958af012102f5188df1da92ed818581c29778047800ed6635788aa09d9469f7d17628f7323300000000"
        )
        // This is a random, longer mainnet transaction.
        val tx2 = Transaction.read(
            "0200000000010142180a8812fc79a3da7fb2471eff3e22d7faee990604c2ba7f2fc8dfb15b550a0200000000feffffff030f241800000000001976a9146774040642a78ca3b8b395e70f8391b21ec026fc88ac4a155801000000001600148d2e0b57adcb8869e603fd35b5179caf053361253b1d010000000000160014e032f4f4b9f8611df0d30a20648c190c263bbc33024730440220506005aa347f5b698542cafcb4f1a10250aeb52a609d6fd67ef68f9c1a5d954302206b9bb844343f4012bccd9d08a0f5430afb9549555a3252e499be7df97aae477a012103976d6b3eea3de4b056cd88cdfd50a22daf121e0fb5c6e45ba0f40e1effbd275a00000000"
        )
        val testCases = listOf(
            // @formatter:off
            TxAddInput(channelId1, 561, tx1, 1, 5u) to ByteVector("0042 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0000000000000231 00f7 020000000001014ade359c5deb7c1cde2e94f401854658f97d7fa31c17ce9a831db253120a0a410100000017160014eb9a5bd79194a23d19d6ec473c768fb74f9ed32cffffffff021ca408000000000017a914946118f24bb7b37d5e9e39579e4a411e70f5b6a08763e703000000000017a9143638b2602d11f934c04abc6adb1494f69d1f14af8702473044022059ddd943b399211e4266a349f26b3289979e29f9b067792c6cfa8cc5ae25f44602204d627a5a5b603d0562e7969011fb3d64908af90a3ec7c876eaa9baf61e1958af012102f5188df1da92ed818581c29778047800ed6635788aa09d9469f7d17628f7323300000000 00000001 00000005"),
            TxAddInput(channelId2, 0, tx2, 2, 0u) to ByteVector("0042 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 0000000000000000 0100 0200000000010142180a8812fc79a3da7fb2471eff3e22d7faee990604c2ba7f2fc8dfb15b550a0200000000feffffff030f241800000000001976a9146774040642a78ca3b8b395e70f8391b21ec026fc88ac4a155801000000001600148d2e0b57adcb8869e603fd35b5179caf053361253b1d010000000000160014e032f4f4b9f8611df0d30a20648c190c263bbc33024730440220506005aa347f5b698542cafcb4f1a10250aeb52a609d6fd67ef68f9c1a5d954302206b9bb844343f4012bccd9d08a0f5430afb9549555a3252e499be7df97aae477a012103976d6b3eea3de4b056cd88cdfd50a22daf121e0fb5c6e45ba0f40e1effbd275a00000000 00000002 00000000"),
            TxAddInput(channelId1, 561, tx1, 0, 0xfffffffdu) to ByteVector("0042 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0000000000000231 00f7 020000000001014ade359c5deb7c1cde2e94f401854658f97d7fa31c17ce9a831db253120a0a410100000017160014eb9a5bd79194a23d19d6ec473c768fb74f9ed32cffffffff021ca408000000000017a914946118f24bb7b37d5e9e39579e4a411e70f5b6a08763e703000000000017a9143638b2602d11f934c04abc6adb1494f69d1f14af8702473044022059ddd943b399211e4266a349f26b3289979e29f9b067792c6cfa8cc5ae25f44602204d627a5a5b603d0562e7969011fb3d64908af90a3ec7c876eaa9baf61e1958af012102f5188df1da92ed818581c29778047800ed6635788aa09d9469f7d17628f7323300000000 00000000 fffffffd"),
            TxAddInput(channelId1, 561, OutPoint(tx1, 1), 5u) to ByteVector("0042 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0000000000000231 0000 00000001 00000005 fd04512006f125a8ef64eb5a25826190dc28f15b85dc1adcfc7a178eef393ea325c02e1f"),
            TxAddOutput(channelId1, 1105, 2047.sat, ByteVector("00149357014afd0ccd265658c9ae81efa995e771f472")) to ByteVector("0043 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0000000000000451 00000000000007ff 0016 00149357014afd0ccd265658c9ae81efa995e771f472"),
            TxRemoveInput(channelId2, 561) to ByteVector("0044 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 0000000000000231"),
            TxRemoveOutput(channelId1, 1) to ByteVector("0045 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0000000000000001"),
            TxComplete(channelId1) to ByteVector("0046 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            TxSignatures(channelId1, tx2, listOf(ScriptWitness(listOf(ByteVector("dead"), ByteVector("beef"))), ScriptWitness(listOf(ByteVector(""), ByteVector("01010101"), ByteVector(""), ByteVector("02")))), null) to ByteVector("0047 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa fc7aa8845f192959202c1b7ff704e7cbddded463c05e844676a94ccb4bed69f1 0002 00020002dead0002beef 0004 00000004010101010000000102"),
            TxSignatures(channelId1, tx2, listOf(ScriptWitness(listOf(ByteVector("dead"), ByteVector("beef"))), ScriptWitness(listOf(ByteVector(""), ByteVector("01010101"), ByteVector(""), ByteVector("02")))), signature) to ByteVector("0047 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa fc7aa8845f192959202c1b7ff704e7cbddded463c05e844676a94ccb4bed69f1 0002 00020002dead0002beef 0004 00000004010101010000000102 fd0259 40 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            TxSignatures(channelId2, tx1, listOf(), null) to ByteVector("0047 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1f2ec025a33e39ef8e177afcdc1adc855bf128dc906182255aeb64efa825f106 0000"),
            TxSignatures(channelId2, tx1, listOf(), signature) to ByteVector("0047 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1f2ec025a33e39ef8e177afcdc1adc855bf128dc906182255aeb64efa825f106 0000 fd0259 40 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            TxInitRbf(channelId1, 8388607, FeeratePerKw(4000.sat)) to ByteVector("0048 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 007fffff 00000fa0"),
            TxInitRbf(channelId1, 0, FeeratePerKw(4000.sat), TlvStream(listOf(TxInitRbfTlv.SharedOutputContributionTlv(5000.sat)))) to ByteVector("0048 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 00000000 00000fa0 00021388"),
            TxAckRbf(channelId2) to ByteVector("0049 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            TxAckRbf(channelId2, TlvStream(listOf(TxAckRbfTlv.SharedOutputContributionTlv(450_000.sat)))) to ByteVector("0049 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 000306ddd0"),
            TxAbort(channelId1, "") to ByteVector("004a aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0000"),
            TxAbort(channelId1, "internal error") to ByteVector("004a aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 000e 696e7465726e616c206572726f72"),
            // @formatter:on
        )
        testCases.forEach { (message, bin) ->
            val decoded = LightningMessage.decode(bin.toByteArray())
            assertNotNull(decoded)
            assertEquals(decoded, message)
            val encoded = LightningMessage.encode(message)
            assertEquals(encoded.byteVector(), bin)
        }
    }

    @Test
    fun `encode - decode channel_reestablish`() {
        val channelReestablish = ChannelReestablish(
            ByteVector32("c11b8fbd682b3c6ee11f9d7268e22bb5887cd4d3bf3338bfcc340583f685733c"),
            242842,
            42,
            PrivateKey.fromHex("34f159d37cf7b5de52ec0adc3968886232f90d272e8c82e8b6f7fcb7e57c4b55"),
            PublicKey.fromHex("02bf050efff417efc09eb211ca9e4e845920e2503740800e88505b25e6f0e1e867")
        )
        val encoded = LightningMessage.encode(channelReestablish)
        val expected =
            "0088c11b8fbd682b3c6ee11f9d7268e22bb5887cd4d3bf3338bfcc340583f685733c000000000003b49a000000000000002a34f159d37cf7b5de52ec0adc3968886232f90d272e8c82e8b6f7fcb7e57c4b5502bf050efff417efc09eb211ca9e4e845920e2503740800e88505b25e6f0e1e867"
        assertEquals(expected, Hex.encode(encoded))
    }

    @Test
    fun `encode - decode channel_update`() {
        val channelUpdate = ChannelUpdate(
            randomBytes64(),
            randomBytes32(),
            ShortChannelId(561),
            1105,
            0,
            1,
            CltvExpiryDelta(144),
            100.msat,
            0.msat,
            10,
            null
        )
        val encoded = LightningMessage.encode(channelUpdate)
        val decoded = LightningMessage.decode(encoded)
        assertEquals(channelUpdate, decoded)
    }

    @Test
    fun `decode channel_update with htlc_maximum_msat`() {
        // this was generated by c-lightning
        val encoded =
            ByteVector("010258fff7d0e987e2cdd560e3bb5a046b4efe7b26c969c2f51da1dceec7bcb8ae1b634790503d5290c1a6c51d681cf8f4211d27ed33a257dcc1102862571bf1792306226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0005a100000200005bc75919010100060000000000000001000000010000000a000000003a699d00")
        val decoded = LightningMessage.decode(encoded.toByteArray())
        val expected = ChannelUpdate(
            ByteVector64("58fff7d0e987e2cdd560e3bb5a046b4efe7b26c969c2f51da1dceec7bcb8ae1b634790503d5290c1a6c51d681cf8f4211d27ed33a257dcc1102862571bf17923"),
            ByteVector32("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"),
            ShortChannelId(0x5a10000020000L),
            1539791129,
            1,
            1,
            CltvExpiryDelta(6),
            1.msat,
            1.msat,
            10,
            980000000.msat
        )
        assertEquals(expected, decoded)
        val reEncoded = LightningMessage.encode(decoded).toByteVector()
        assertEquals(encoded, reEncoded)
    }

    @Test
    fun `encode - decode channel_update with unknown trailing bytes`() {
        val channelUpdate = ChannelUpdate(
            randomBytes64(),
            randomBytes32(),
            ShortChannelId(561),
            1105,
            0,
            1,
            CltvExpiryDelta(144),
            0.msat,
            10.msat,
            10,
            null,
            ByteVector("010203")
        )
        val encoded = LightningMessage.encode(channelUpdate)
        val decoded = LightningMessage.decode(encoded)
        assertEquals(channelUpdate, decoded)
    }

    @Test
    fun `encode - decode channel_announcement`() {
        val testCases = listOf(
            ChannelAnnouncement(
                randomBytes64(),
                randomBytes64(),
                randomBytes64(),
                randomBytes64(),
                Features(Hex.decode("09004200")),
                randomBytes32(),
                ShortChannelId(42),
                randomKey().publicKey(),
                randomKey().publicKey(),
                randomKey().publicKey(),
                randomKey().publicKey()
            ),
            ChannelAnnouncement(
                randomBytes64(),
                randomBytes64(),
                randomBytes64(),
                randomBytes64(),
                Features(mapOf()),
                randomBytes32(),
                ShortChannelId(42),
                randomKey().publicKey(),
                randomKey().publicKey(),
                randomKey().publicKey(),
                randomKey().publicKey(),
                ByteVector("01020304")
            ),
        )

        testCases.forEach {
            val encoded = LightningMessage.encode(it)
            val decoded = LightningMessage.decode(encoded)
            assertNotNull(decoded)
            assertEquals(it, decoded)
        }
    }

    @Test
    fun `encode - decode closing_signed`() {
        val defaultSig = ByteVector64("01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101")
        val testCases = listOf(
            Hex.decode("0027 0100000000000000000000000000000000000000000000000000000000000000 0000000000000000 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") to ClosingSigned(
                ByteVector32.One,
                0.sat,
                ByteVector64.Zeroes
            ),
            Hex.decode("0027 0100000000000000000000000000000000000000000000000000000000000000 00000000000003e8 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") to ClosingSigned(
                ByteVector32.One,
                1000.sat,
                ByteVector64.Zeroes
            ),
            Hex.decode("0027 0100000000000000000000000000000000000000000000000000000000000000 00000000000005dc 01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101") to ClosingSigned(
                ByteVector32.One,
                1500.sat,
                defaultSig
            ),
            Hex.decode("0027 0100000000000000000000000000000000000000000000000000000000000000 00000000000005dc 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 0110000000000000006400000000000007d0") to ClosingSigned(
                ByteVector32.One,
                1500.sat,
                ByteVector64.Zeroes,
                TlvStream(listOf(ClosingSignedTlv.FeeRange(100.sat, 2000.sat)))
            ),
            Hex.decode("0027 0100000000000000000000000000000000000000000000000000000000000000 00000000000003e8 01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101 0110000000000000006400000000000007d0") to ClosingSigned(
                ByteVector32.One,
                1000.sat,
                defaultSig,
                TlvStream(listOf(ClosingSignedTlv.FeeRange(100.sat, 2000.sat)))
            ),
            Hex.decode("0027 0100000000000000000000000000000000000000000000000000000000000000 0000000000000064 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 0110000000000000006400000000000003e8 030401020304") to ClosingSigned(
                ByteVector32.One,
                100.sat,
                ByteVector64.Zeroes,
                TlvStream(listOf(ClosingSignedTlv.FeeRange(100.sat, 1000.sat)), listOf(GenericTlv(3, ByteVector("01020304"))))
            ),
        )

        testCases.forEach {
            val decoded = LightningMessage.decode(it.first)
            assertNotNull(decoded)
            assertEquals(decoded, it.second)
            val reEncoded = LightningMessage.encode(decoded)
            assertArrayEquals(reEncoded, it.first)
        }
    }

    @Test
    fun `nonreg backup channel data`() {
        val channelId = randomBytes32()
        val txHash = randomBytes32()
        val signature = randomBytes64()
        val key = randomKey()
        val point = randomKey().publicKey()
        val randomData = randomBytes(42)

        // @formatter:off
        val refs = mapOf(
            // channel_reestablish
            Hex.decode("0088") + channelId.toByteArray() + Hex.decode("0001020304050607 0809aabbccddeeff") + key.value.toByteArray() + point.value.toByteArray() to ChannelReestablish(channelId, 0x01020304050607L, 0x0809aabbccddeeffL, key, point),
            Hex.decode("0088") + channelId.toByteArray() + Hex.decode("0001020304050607 0809aabbccddeeff") + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("01 02 0102") to ChannelReestablish(channelId, 0x01020304050607L, 0x0809aabbccddeeffL, key, point, TlvStream(listOf(), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0088") + channelId.toByteArray() + Hex.decode("0001020304050607 0809aabbccddeeff") + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("fe47010000 00") to ChannelReestablish(channelId, 0x01020304050607L, 0x0809aabbccddeeffL, key, point, TlvStream(listOf(ChannelReestablishTlv.ChannelData(EncryptedChannelData.empty)))),
            Hex.decode("0088") + channelId.toByteArray() + Hex.decode("0001020304050607 0809aabbccddeeff") + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("01 02 0102") + Hex.decode("fe47010000 00") to ChannelReestablish(channelId, 0x01020304050607L, 0x0809aabbccddeeffL, key, point, TlvStream(listOf(ChannelReestablishTlv.ChannelData(EncryptedChannelData(ByteVector.empty))), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0088") + channelId.toByteArray() + Hex.decode("0001020304050607 0809aabbccddeeff") + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("fe47010000 07 bbbbbbbbbbbbbb") to ChannelReestablish(channelId, 0x01020304050607L, 0x0809aabbccddeeffL, key, point).withChannelData(ByteVector("bbbbbbbbbbbbbb")),
            Hex.decode("0088") + channelId.toByteArray() + Hex.decode("0001020304050607 0809aabbccddeeff") + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("01 02 0102") + Hex.decode("fe47010000 07 bbbbbbbbbbbbbb") to ChannelReestablish(channelId, 0x01020304050607L, 0x0809aabbccddeeffL, key, point, TlvStream(listOf(ChannelReestablishTlv.ChannelData(EncryptedChannelData(ByteVector("bbbbbbbbbbbbbb")))), listOf(GenericTlv(1, ByteVector("0102"))))),
            // tx_signatures
            Hex.decode("0047") + channelId.toByteArray() + txHash.toByteArray() + Hex.decode("0000") to TxSignatures(channelId, txHash, listOf()),
            Hex.decode("0047") + channelId.toByteArray() + txHash.toByteArray() + Hex.decode("0000 fe47010000 00") to TxSignatures(channelId, txHash, listOf(), TlvStream(listOf(TxSignaturesTlv.ChannelData(EncryptedChannelData.empty)))),
            Hex.decode("0047") + channelId.toByteArray() + txHash.toByteArray() + Hex.decode("0000 fe47010000 04 deadbeef") to TxSignatures(channelId, txHash, listOf(), TlvStream(listOf(TxSignaturesTlv.ChannelData(EncryptedChannelData(ByteVector("deadbeef")))))),
            Hex.decode("0047") + channelId.toByteArray() + txHash.toByteArray() + Hex.decode("0000 2b012a fe47010000 04 deadbeef") to TxSignatures(channelId, txHash, listOf(), TlvStream(listOf(TxSignaturesTlv.ChannelData(EncryptedChannelData(ByteVector("deadbeef")))), listOf(GenericTlv(43, ByteVector("2a"))))),
            // commit_sig
            Hex.decode("0084") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("0000") to CommitSig(channelId, signature, listOf()),
            Hex.decode("0084") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("0000") + Hex.decode("01 02 0102") to CommitSig(channelId, signature, listOf(), TlvStream(listOf(), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0084") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("0000 fe47010000 00") to CommitSig(channelId, signature, listOf(), TlvStream(listOf(CommitSigTlv.ChannelData(EncryptedChannelData.empty)))),
            Hex.decode("0084") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("0000 01020102 fe47010000 00") to CommitSig(channelId, signature, listOf(), TlvStream(listOf(CommitSigTlv.ChannelData(EncryptedChannelData.empty)), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0084") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("0000 fe47010000 07 cccccccccccccc") to CommitSig(channelId, signature, listOf()).withChannelData(ByteVector("cccccccccccccc")),
            Hex.decode("0084") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("0000 01020102 fe47010000 07 cccccccccccccc") to CommitSig(channelId, signature, listOf(), TlvStream(listOf(CommitSigTlv.ChannelData(EncryptedChannelData(ByteVector("cccccccccccccc")))), listOf(GenericTlv(1, ByteVector("0102"))))),
            // revoke_and_ack
            Hex.decode("0085") + channelId.toByteArray() + key.value.toByteArray() + point.value.toByteArray() to RevokeAndAck(channelId, key, point),
            Hex.decode("0085") + channelId.toByteArray() + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("01 02 0102") to RevokeAndAck(channelId, key, point, TlvStream(listOf(), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0085") + channelId.toByteArray() + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("fe47010000 00") to RevokeAndAck(channelId, key, point, TlvStream(listOf(RevokeAndAckTlv.ChannelData(EncryptedChannelData.empty)))),
            Hex.decode("0085") + channelId.toByteArray() + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("01 02 0102") + Hex.decode("fe47010000 00") to RevokeAndAck(channelId, key, point, TlvStream(listOf(RevokeAndAckTlv.ChannelData(EncryptedChannelData.empty)), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0085") + channelId.toByteArray() + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("fe47010000 07 cccccccccccccc") to RevokeAndAck(channelId, key, point).withChannelData(ByteVector("cccccccccccccc")),
            Hex.decode("0085") + channelId.toByteArray() + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("01 02 0102") + Hex.decode("fe47010000 07 cccccccccccccc") to RevokeAndAck(channelId, key, point, TlvStream(listOf(RevokeAndAckTlv.ChannelData(EncryptedChannelData(ByteVector("cccccccccccccc")))), listOf(GenericTlv(1, ByteVector("0102"))))),
            // shutdown
            Hex.decode("0026") + channelId.toByteArray() + Hex.decode("002a") + randomData to Shutdown(channelId, randomData.toByteVector()),
            Hex.decode("0026") + channelId.toByteArray() + Hex.decode("002a") + randomData + Hex.decode("01 02 0102") to Shutdown(channelId, randomData.toByteVector(), TlvStream(listOf(), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0026") + channelId.toByteArray() + Hex.decode("002a") + randomData + Hex.decode("fe47010000 00") to Shutdown(channelId, randomData.toByteVector(), TlvStream(listOf(ShutdownTlv.ChannelData(EncryptedChannelData.empty)))),
            Hex.decode("0026") + channelId.toByteArray() + Hex.decode("002a") + randomData + Hex.decode("01 02 0102") + Hex.decode("fe47010000 00") to Shutdown(channelId, randomData.toByteVector(), TlvStream(listOf(ShutdownTlv.ChannelData(EncryptedChannelData.empty)), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0026") + channelId.toByteArray() + Hex.decode("002a") + randomData + Hex.decode("fe47010000 07 cccccccccccccc") to Shutdown(channelId, randomData.toByteVector()).withChannelData(ByteVector("cccccccccccccc")),
            Hex.decode("0026") + channelId.toByteArray() + Hex.decode("002a") + randomData + Hex.decode("01 02 0102") + Hex.decode("fe47010000 07 cccccccccccccc") to Shutdown(channelId, randomData.toByteVector(), TlvStream(listOf(ShutdownTlv.ChannelData(EncryptedChannelData(ByteVector("cccccccccccccc")))), listOf(GenericTlv(1, ByteVector("0102"))))),
            // closing_signed
            Hex.decode("0027") + channelId.toByteArray() + Hex.decode("00000000075bcd15") + signature.toByteArray() to ClosingSigned(channelId, 123456789.sat, signature),
            Hex.decode("0027") + channelId.toByteArray() + Hex.decode("00000000075bcd15") + signature.toByteArray() + Hex.decode("03 02 0102") to ClosingSigned(channelId, 123456789.sat, signature, TlvStream(listOf(), listOf(GenericTlv(3, ByteVector("0102"))))),
            Hex.decode("0027") + channelId.toByteArray() + Hex.decode("00000000075bcd15") + signature.toByteArray() + Hex.decode("fe47010000 00") to ClosingSigned(channelId, 123456789.sat, signature, TlvStream(listOf(ClosingSignedTlv.ChannelData(EncryptedChannelData.empty)))),
            Hex.decode("0027") + channelId.toByteArray() + Hex.decode("00000000075bcd15") + signature.toByteArray() + Hex.decode("03 02 0102") + Hex.decode("fe47010000 00") to ClosingSigned(channelId, 123456789.sat, signature, TlvStream(listOf(ClosingSignedTlv.ChannelData(EncryptedChannelData.empty)), listOf(GenericTlv(3, ByteVector("0102"))))),
            Hex.decode("0027") + channelId.toByteArray() + Hex.decode("00000000075bcd15") + signature.toByteArray() + Hex.decode("fe47010000 07 cccccccccccccc") to ClosingSigned(channelId, 123456789.sat, signature).withChannelData(ByteVector("cccccccccccccc")),
            Hex.decode("0027") + channelId.toByteArray() + Hex.decode("00000000075bcd15") + signature.toByteArray() + Hex.decode("03 02 0102") + Hex.decode("fe47010000 07 cccccccccccccc") to ClosingSigned(channelId, 123456789.sat, signature, TlvStream(listOf(ClosingSignedTlv.ChannelData(EncryptedChannelData(ByteVector("cccccccccccccc")))), listOf(GenericTlv(3, ByteVector("0102")))))
        )
        // @formatter:on

        refs.forEach {
            val decoded = LightningMessage.decode(it.key)
            assertEquals(it.value, decoded)
            val encoded = LightningMessage.encode(it.value)
            assertArrayEquals(it.key, encoded)
        }
    }

    @Test
    fun `skip backup channel data when too large`() {
        // We omit the channel backup when it risks overflowing the lightning message.
        val belowLimit = EncryptedChannelData(ByteVector(ByteArray(59500) { 42 }))
        val aboveLimit = EncryptedChannelData(ByteVector(ByteArray(60000) { 42 }))
        val messages = listOf(
            ChannelReestablish(randomBytes32(), 0, 0, randomKey(), randomKey().publicKey()),
            TxSignatures(randomBytes32(), randomBytes32(), listOf()),
            CommitSig(randomBytes32(), randomBytes64(), listOf()),
            RevokeAndAck(randomBytes32(), randomKey(), randomKey().publicKey()),
            Shutdown(randomBytes32(), ByteVector("deadbeef")),
            ClosingSigned(randomBytes32(), 0.sat, randomBytes64()),
        )
        messages.forEach {
            assertEquals(it.withChannelData(belowLimit).channelData, belowLimit)
            assertTrue(it.withChannelData(aboveLimit).channelData.isEmpty())
        }
    }

    @Test
    fun `skip backup channel data when message is too large`() {
        val channelData = EncryptedChannelData(ByteVector(ByteArray(59500) { 42 }))
        val smallCommit = CommitSig(randomBytes32(), randomBytes64(), listOf())
        assertEquals(smallCommit.withChannelData(channelData).channelData, channelData)
        val largeCommit = CommitSig(randomBytes32(), randomBytes64(), List(50) { randomBytes64() })
        assertTrue(largeCommit.withChannelData(channelData).channelData.isEmpty())
    }

    @Test
    fun `encode - decode pay-to-open messages`() {
        val testCases = listOf(
            PayToOpenRequest(randomBytes32(), 10_000.sat, 5_000.msat, 100.msat, 10.sat, randomBytes32(), 100, OnionRoutingPacket(0, randomKey().publicKey().value, ByteVector("0102030405"), randomBytes32())),
            PayToOpenResponse(randomBytes32(), randomBytes32(), PayToOpenResponse.Result.Success(randomBytes32())),
            PayToOpenResponse(randomBytes32(), randomBytes32(), PayToOpenResponse.Result.Failure(null)),
            PayToOpenResponse(randomBytes32(), randomBytes32(), PayToOpenResponse.Result.Failure(ByteVector("deadbeef"))),
        )

        testCases.forEach {
            val encoded = LightningMessage.encode(it)
            val decoded = LightningMessage.decode(encoded)
            assertNotNull(decoded)
            assertEquals(it, decoded)
        }
    }

    @Test
    fun `encode - decode please-open-channel messages`() {
        val testCases = listOf(
            // @formatter:off
            PleaseOpenChannel(Block.RegtestGenesisBlock.hash, ByteVector32("2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25"), 123_456.sat, 2, 522_000) to Hex.decode("8ca1 06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f 2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25 000000000001e240 0002 0007f710"),
            PleaseOpenChannel(Block.RegtestGenesisBlock.hash, ByteVector32("2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25"), 123_456.sat, 2, 522_000, TlvStream(listOf(PleaseOpenChannelTlv.MaxFees(8, 3_000.sat)))) to Hex.decode("8ca1 06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f 2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25 000000000001e240 0002 0007f710 010a00080000000000000bb8"),
            PleaseOpenChannel(Block.RegtestGenesisBlock.hash, ByteVector32("2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25"), 123_456.sat, 2, 522_000, TlvStream(listOf(PleaseOpenChannelTlv.GrandParents(listOf())))) to Hex.decode("8ca1 06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f 2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25 000000000001e240 0002 0007f710 fd023100"),
            PleaseOpenChannel(Block.RegtestGenesisBlock.hash, ByteVector32("2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25"), 123_456.sat, 2, 522_000, TlvStream(listOf(PleaseOpenChannelTlv.GrandParents(listOf(OutPoint(ByteVector32("d0556c8cc004933f40b9ca5e87e18cb549298fb02d7e64b0c0ee95303485145a"), 5)))))) to Hex.decode("8ca1 06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f 2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25 000000000001e240 0002 0007f710 fd023128d0556c8cc004933f40b9ca5e87e18cb549298fb02d7e64b0c0ee95303485145a0000000000000005"),
            PleaseOpenChannel(Block.RegtestGenesisBlock.hash, ByteVector32("2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25"), 123_456.sat, 2, 522_000, TlvStream(listOf(PleaseOpenChannelTlv.GrandParents(listOf(OutPoint(ByteVector32("572b045edb5f0e3ff667e914e368273b11a874fae56a735b332b54048b7978c2"), 0), OutPoint(ByteVector32("cd6ac843158a1c317021de1323cdd2071f0f59744f79b298a8a45fda2dd7989f"), 1105)))))) to Hex.decode("8ca1 06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f 2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25 000000000001e240 0002 0007f710 fd023150572b045edb5f0e3ff667e914e368273b11a874fae56a735b332b54048b7978c20000000000000000cd6ac843158a1c317021de1323cdd2071f0f59744f79b298a8a45fda2dd7989f0000000000000451"),
            // @formatter:on
        )

        testCases.forEach {
            val decoded = LightningMessage.decode(it.second)
            assertNotNull(decoded)
            assertEquals(it.first, decoded)
            val encoded = LightningMessage.encode(decoded)
            assertArrayEquals(it.second, encoded)
        }
    }

    @Test
    fun `encode - decode please-open-channel-rejected messages`() {
        val testCases = listOf(
            // @formatter:off
            PleaseOpenChannelRejected(ByteVector32("2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25"), PleaseOpenChannelFailure.FeeInsufficient, TlvStream(listOf(PleaseOpenChannelRejectedTlv.ExpectedFees(1_578_000.msat)))) to Hex.decode("8ca3 2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25 00000001 0103181410"),
            PleaseOpenChannelRejected(ByteVector32("2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25"), PleaseOpenChannelFailure.FeeInsufficient, TlvStream(listOf(PleaseOpenChannelRejectedTlv.ExpectedFees(3_000_000.msat)))) to Hex.decode("8ca3 2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25 00000001 01032dc6c0"),
            PleaseOpenChannelRejected(ByteVector32("2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25"), PleaseOpenChannelFailure.Unknown(113)) to Hex.decode("8ca3 2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25 00000071"),
            PleaseOpenChannelRejected(ByteVector32("2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25"), PleaseOpenChannelFailure.Unknown(113), TlvStream(listOf(), listOf(GenericTlv(57, ByteVector("deadbeef"))))) to Hex.decode("8ca3 2dadacd65b585e4061421b5265ff543e2a7bdc4d4a7fea932727426bdc53db25 00000071 3904deadbeef"),
            // @formatter:on
        )

        testCases.forEach {
            val decoded = LightningMessage.decode(it.second)
            assertNotNull(decoded)
            assertEquals(it.first, decoded)
            val encoded = LightningMessage.encode(decoded)
            assertArrayEquals(it.second, encoded)
        }
    }

    @Test
    fun `encode - decode swap-out messages`() {
        // @formatter:off
        val testCases = listOf(
            Pair(
                SwapOutRequest(chainHash = Block.TestnetGenesisBlock.blockId, amount = 50_000.sat, bitcoinAddress = "mjbGousCmfvwUU5rjjfCqVCPUyJcG4ULTj", feePerKw = 1234),
                Hex.decode("88c3000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943000000000000c35000226d6a62476f7573436d667677555535726a6a66437156435055794a634734554c546a000004d2")
            ),
            Pair(
                SwapOutResponse(chainHash = Block.TestnetGenesisBlock.blockId, amount = 50_000.sat, fee = 2008.sat, paymentRequest = "lntb10u1p38u3zfpp5asmmcmrn8p67shh0gnlzrn29qe3mdxm3hwa804849px3fvnuevesdq5xysyymr0ddskxcmfdehsxqrrsscqp79qy9qsqsp58zcu2wgulksypzahmfpn9l6z3exrx6arzkn6adfrcq38khphjpjq2jrt699w4jexg0crzl4kr0q8kqpffeqvpchcdcy7tarhnpllpqw85zpxkgg5nwqtckggrvckz5x4mfnd8tecy8cwzwxuak6553j2dxqqr2q2u7"),
                Hex.decode("88c5000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943000000000000c35000000000000007d801136c6e74623130753170333875337a6670703561736d6d636d726e3870363773686830676e6c7a726e32397165336d64786d3368776138303438343970783366766e756576657364713578797379796d72306464736b78636d66646568737871727273736371703739717939717371737035387a6375327767756c6b7379707a61686d66706e396c367a33657872783661727a6b6e3661646672637133386b6870686a706a71326a727436393977346a6578673063727a6c346b723071386b717066666571767063686364637937746172686e706c6c70717738357a70786b6767356e777174636b67677276636b7a3578346d666e6438746563793863777a777875616b363535336a3264787171723271327537")
            ),
        )
        // @formatter:on
        testCases.forEach {
            val decoded = LightningMessage.decode(it.second)
            assertNotNull(decoded)
            assertEquals(it.first, decoded)
            val encoded = LightningMessage.encode(decoded)
            assertArrayEquals(it.second, encoded)
        }
    }

    @Test
    fun `encode - decode phoenix-android-legacy-info messages`() {
        val testCases = listOf(
            Pair(PhoenixAndroidLegacyInfo(hasChannels = true), Hex.decode("88cfff")),
            Pair(PhoenixAndroidLegacyInfo(hasChannels = false), Hex.decode("88cf00")),
        )
        testCases.forEach {
            val decoded = LightningMessage.decode(it.second)
            assertNotNull(decoded)
            assertEquals(it.first, decoded)
            val encoded = LightningMessage.encode(decoded)
            assertArrayEquals(it.second, encoded)
        }
    }
}