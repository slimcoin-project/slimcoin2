// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <deploymentinfo.h>
#include <hash.h> // for signet block challenge hash
#include <util/system.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTimeTx, uint32_t nTimeBlock, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(9999) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward; // SLM note: SLM's genesis block says txNew.vout[0].SetEmpty()
    txNew.vout[0].scriptPubKey = genesisOutputScript;
    txNew.nTime = nTimeTx;

    CBlock genesis;
    genesis.nTime    = nTimeBlock;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTimeTx, uint32_t nTimeBlock, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char *pszTimestamp = "RT: 2 southeast Ukranian regions to hold referendum May 11 as planned"; // SLM
    // const char* pszTimestamp = "Matonis 07-AUG-2012 Parallel Currencies And The Roadmap To Monetary Freedom";
    const CScript genesisOutputScript = CScript();
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTimeTx, nTimeBlock, nNonce, nBits, nVersion, genesisReward);
}


/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        // TODO: SLM has a time for that (main.cpp):  int64 nBIP16SwitchTime = fTestNet ? 1329264000 : 1333238400; but it doesn't make sense as this is mar 14 feb 2012 21:00:00 SLM was created later ...
        //consensus.BIP16Height = 0;
        consensus.BIP34Height = 99999999; // 339994;
        consensus.BIP34Hash = uint256S("0000000000000000000000000000000000000000000000000000000000000000"); // dummy value. uint256S("000000000000000237f50af4cfe8924e8693abc5bd8ae5abb95bc6d230f5953f");
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 20;
        // consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 32;
        consensus.bnInitialHashTarget = uint256S("000007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 21;
        // consensus.bnInitialHashTarget = uint256S("0000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 40;

        // SLM specific - moved to chain.h
        // consensus.nPoWBase = uint256S("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // nPoWBase(~uint256(0) >> 24);
        // consensus.nPoBBase = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // nPoBBase(~uint256(0) >> 20);

        // consensus.nTargetTimespan = getTargetTimespan(lastNHeight);
        consensus.nTargetTimespan = 6 * 60 * 60; // SLM: from Block 4258 on
        consensus.nTargetTimespanBefore4258 = 30 * 60; // SLM: until block 4257
        // consensus.nTargetTimespan = 7 * 24 * 60 * 60;  // one week
        consensus.nStakeTargetSpacing = 90; // SLM: 90 second block spacing (STAKE_TARGET_SPACING)
        // consensus.nStakeTargetSpacing = 10 * 60; // 10-minute block spacing
        consensus.nTargetSpacingWorkMax = 10 * consensus.nStakeTargetSpacing; // SLM: 15 min
        // consensus.nTargetSpacingWorkMax = 12 * consensus.nStakeTargetSpacing; // 2-hour
        // consensus.nPowTargetSpacing = min(nTargetSpacingWorkMax, consensus.nStakeTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight));
        consensus.nPowTargetSpacing = consensus.nStakeTargetSpacing; // SLM: we leave this unchanged, let's see what happens.
        consensus.nStakeMinAge = 60 * 60 * 24 * 7; // SLM: minimum age for coin age = 7 days
        // consensus.nStakeMinAge = 60 * 60 * 24 * 30; // minimum age for coin age
        consensus.nStakeMaxAge = 60 * 60 * 24 * 90; // SLM like PPC
        consensus.nModifierInterval = 6 * 60 * 60; // Modifier interval: time to elapse before new modifier is computed - SLM like PPC
        consensus.nCoinbaseMaturity = 500; // SLM like PPC

        consensus.fPowAllowMinDifficultyBlocks = false; // should be ok this way.
        consensus.fPowNoRetargeting = false; // TODO: not in SLM, perhaps set to true?
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016 - TODO: probably softfork-related
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing - TODO: probably softfork-related

        consensus.SegwitHeight = 99999999; // 455470; // TODO: unset this or set to extremely high number?

        // TODO nMinimumChainWork is the work done at approx. the block in defaultAssumeValid.
        // https://bitcoin.stackexchange.com/questions/72051/what-is-nminimumchainwork
        // https://bitcoin.stackexchange.com/questions/51112/how-to-get-bip34hash-and-nminimumchainwork
        // we probably need to run getblockchaininfo once to get this value, as getinfo/getmininginfo doesn't include it.
        // for now we use a dummy value, equivalent to a difficulty of 1.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000100010001");
        //consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000516e58fb3669ea"); // 650000
        consensus.defaultAssumeValid = uint256S("0000000197d6fbba2311e3fdcdb2e0fde938fb8b2dd7f5ea70531d16a9b6c95e"); // SLM block 3000000
        //consensus.defaultAssumeValid = uint256S("0x3125be5493e80431952593cce42b160019671108103735509238830939e1c9a3");  // 650000

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */

        // likely we only need the pchMessageStartSLIMCoin string, as the switch time is not block time but system time.
        // SLIMCoin message start (switch from Bitcoin's in v0.2) //
        //pchMessageStartBitcoin[4] = { 0x9f, 0xeb, 0x1b, 0x8a }; // do we still need this?
        //pchMessageStartSLIMCoin[4] = { 0x6e, 0x8b, 0x92, 0xa5 }; // this is also used in main.cpp LoadExternalBlockFile
        //nMessageStartSwitchTime = 1400000000;

        // original SLM:
        // pchMessageStart[4] = { 0x6e, 0x8b, 0x92, 0xa5 }
        pchMessageStart[0] = 0x6e;
        pchMessageStart[1] = 0x8b;
        pchMessageStart[2] = 0x92;
        pchMessageStart[3] = 0xa5;

        //pchMessageStart[0] = 0xe6; // original PPC { 0xe6, 0xe8, 0xe9, 0xe5 }
        //pchMessageStart[1] = 0xe8;
        //pchMessageStart[2] = 0xe9;
        //pchMessageStart[3] = 0xe5;

        nDefaultPort = 41682; // 9901;
        nPruneAfterHeight = 100000; // can probably stay at that number, before this block nothing is pruned.
        m_assumed_blockchain_size = 5; // 2; // this seems to be expected chain size in GB (10% overhead recommended)


        // CreateGenesisBlock(uint32_t nTimeTx, uint32_t nTimeBlock, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
        genesis = CreateGenesisBlock(1399578460, 1399578460, 116872u, 0x1e0fffff, 1, 0); // the "u" is unsigned. TODO -> in original code it's without u
        // genesis = CreateGenesisBlock(1345083810, 1345084287, 2179302059u, 0x1d00ffff, 1, 0); // TODO (see params above) // PPC
        consensus.hashGenesisBlock = genesis.GetHash(); // TODO do we need Dcrypt for this?
        // disabled assertions due to Dcrypt missing.
        // assert(consensus.hashGenesisBlock == uint256S("0x00000766be5a4bb74c040b85a98d2ba2b433c5f4c673912b3331ea6f18d61bea")); // SLM -> disabled
        //assert(consensus.hashGenesisBlock == uint256S("0x0000000032fe677166d54963b62a4677d8957e87c508eaa4fd7eb1c880cd27e3"));
        // assert(genesis.hashMerkleRoot == uint256S("0xbae3867d5e5d35c321adaf9610b9e4147a855f9ad319fdcf70913083d783753f")); // SLM -> disabled
        //assert(genesis.hashMerkleRoot == uint256S("0x3c2d8f85fab4d17aac558cc648a1a58acff0de6deb890c29985690052c5993c2"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        //vSeeds.emplace_back("seed.peercoin.net"); // SLM doesn't have seed nodes
        //vSeeds.emplace_back("seed2.peercoin.net");
        //vSeeds.emplace_back("seed.peercoin-library.org");
        //vSeeds.emplace_back("seed.ppcoin.info");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63); // 0x3F // slimcoin: addresses begin with 'S'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125); // 0x7D // slimcoin: addresses begin with 's'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,191); // 0xBF // slimcoin: wif starts with 'V'
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E}; // TODO: not sure about support here (BIP32). These are ppc values.
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4}; // TODO: idem.
        /*base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,55);  // peercoin: addresses begin with 'P'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,117); // peercoin: addresses begin with 'p'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,183);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};*/

        // human readable prefix to bench32 address
        bech32_hrp = "sl"; // "pc"; # TODO up for discussion! (anyway Segwit won't be enabled soon)

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                { 0,       uint256S("0x00000766be5a4bb74c040b85a98d2ba2b433c5f4c673912b3331ea6f18d61bea")},
                { 9012,    uint256S("0x00000006b2c364c71c279977abc8adf528d25263fb3b4fa623a309745d9f6246")}, // SLM mainnet checkpoints
                { 9013,    uint256S("0x000000064ce948cdba2c2223dd75c3677847a00daded6be78a097db82d616eee")},
                { 9201,    uint256S("0x0000000ab86098c475566cf8f494d131c4d17aa18a26e946f6b6143be4989d43")},
                { 9401,    uint256S("0x0000000538be9059aa111cdee43d7f6c5c4e6581073af1f4478a8705f5817f3b")},
                { 10198,   uint256S("0x000000086631340ce44f7ee72e7125654eef62181a08bacf69b42f797fd7bb4c")},
                { 10503,   uint256S("0x1a433766560d719d5ece18aa190b00fd503d733e2162e511df0998df5c8680f5")},
                { 15165,   uint256S("0x0000017fba5ef709509c7380e3e128a69a5ab3c60b526c8345aff592dc8d8f81")},
                { 15935,   uint256S("0xaf377a2f3be16d3c3d82ad9158a3c24b5e8a7a1af6e315b486a390c651d70ff5")},
                { 15936,   uint256S("0x0000002a4ba8fac73286a3cbcac76610a11f3faebec4ce19c13aca30990684f4")},
                { 35587,   uint256S("0x07450307a456afcbc62d8414913a8b4497f4dc13629337b7db5658aa52877155")},
                { 43685,   uint256S("0xa91550beeed702374a01bd8999669cc9dc6952752f2ede01ef446cb0d2113e6f")},
                { 121300,  uint256S("0x6f7f1b5cf35b3be443f747ffdacbc7faba860ec82535dcbe1d1486eed6eea131")},
                { 199633,  uint256S("0x000000048436de97fd78b645a0ccdbd7c57be20172b49eeac42f78571ff45e9a")},
                { 277966,  uint256S("0x00000000328877ab62f47b55df02395e1ca425ee744c41490147d614abf50544")},
                { 356299,  uint256S("0x0000003a779a6620b17a0ee0c093b2ee8e5006572685246bd9e41ed95c99e22d")},
                { 434632,  uint256S("0xb2e53b982227092d1fa84cf771ae2234f457600b5cf9274d30ad810150990239")},
                { 512965,  uint256S("0x000000128da1ec0a285e3ec3e7a319433fe6ae58093a67133959eb7b1e58f935")},
                { 591298,  uint256S("0x00000053148f361c4affc7508f6c92ed4c9bf109cf609c18a9ff7c71828bb764")},
                { 669631,  uint256S("0x00000037214a52c13a7f50ffffc5b3bb8d8ed3be92dbe4b8b342ec527a4d7330")},
                { 747964,  uint256S("0x000000410095e63c64bd3f25ae642464653ada088483f0bc7ed69a609dfc17a0")},
                { 826297,  uint256S("0x000001af75fbae8557d20337dff0bed05222018cf496aa7b53e1fdad99800e42")},
	            { 859045,  uint256S("0xa8deecd84bcc9752ccd65f0affb6ccc30c22aae78cb767d58cb72f0860e21f1e")},
                { 904630,  uint256S("0x0000003ac05d489aa58bd9e28bebf98b612f6a7903b94a900f8b977a3b3a4e86")},
                {1048782,  uint256S("0x0000001a1eeb47d6185648c27717ad171490e8f53c4e298eb5b24305cbac47ff")},
                {1192934,  uint256S("0x00000005c57a715e67ee9e8557536557b60fe7c55b7fa7e858e808aaff80fa9f")},
                {1337086,  uint256S("0x2d4b11ad325000bd79298d3998b3e118c8a5a57eab671b24faf5c1250934ba25")},
                {1481238,  uint256S("0x148a1ee90a66d796c7f30268947866f5abaa63a6c2f3585fdae1de562f97b572")},
                {1625390,  uint256S("0x00000008b2328f5a5f83a34b01bda3e649c13bac672b6a187f0f18bc3a028e3d")},

                /*{     0, uint256S("0x0000000032fe677166d54963b62a4677d8957e87c508eaa4fd7eb1c880cd27e3")}, // PPC checkpoints
                { 19080, uint256S("0x000000000000bca54d9ac17881f94193fd6a270c1bb21c3bf0b37f588a40dbd7")},
                { 30583, uint256S("0xd39d1481a7eecba48932ea5913be58ad3894c7ee6d5a8ba8abeb772c66a6696e")},
                { 99999, uint256S("0x27fd5e1de16a4270eb8c68dee2754a64da6312c7c3a0e99a7e6776246be1ee3f")},
                {219999, uint256S("0xab0dad4b10d2370f009ed6df6effca1ba42f01d5070d6b30afeedf6463fbe7a2")},
                {336000, uint256S("0x4d261cef6e61a5ed8325e560f1d6e36f4698853a4c7134677f47a1d1d842bdf6")},
                {371850, uint256S("0x6b18adcb0a6e080dae85b74eee2b83fabb157bbea64fab0ed2192b2f6d5b89f3")},
                {407813, uint256S("0x00000000000000012730b0f48bed8afbeb08164c9d63597afb082e82ea05cec9")},
                {443561, uint256S("0xf81cea8e4e40b2cfcc13a8bd82436399c35a55df951b95e7128601c1838029ed")},
                {455470, uint256S("0xd1472c26229f90b8589d331aa47ba9023cb953b92dce342c753e7a6b3431bf1e")},
                {479189, uint256S("0xc9c065028b20a23fbb9627bbca5946c7497f11e1f72433d4d215c79047cf06f2")},
                {504051, uint256S("0xff65454ebdf1d89174bec10a3c016db92f7b1d9a4759603472842f254be8d7b3")},
                {589659, uint256S("0x967c14abf21214639aeff0a270c4543cd3b80fe53178384ac5aa3c277662f1d0")},*/
            }
        };

        m_assumeutxo_data = MapAssumeutxo{
         // TODO to be specified in a future patch.
        };


        chainTxData = ChainTxData{
            // Data as of block 0000000197d6fbba2311e3fdcdb2e0fde938fb8b2dd7f5ea70531d16a9b6c95e (height 3000000).
            1672183248, // * UNIX timestamp of last known number of transactions
            3600000,    // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the ChainStateFlushed debug.log lines)
                        // TODO: these values was estimated (1.2 txes per block, 90 sec block time)
            0.013 // * estimated number of transactions per second after that timestamp
                        //   2145533/(1666903503-1345400356) = 0.006673443
        };
        /*chainTxData = ChainTxData{
            // Data as of block 3125be5493e80431952593cce42b160019671108103735509238830939e1c9a3 (height 650000).
            1666903503, // * UNIX timestamp of last known number of transactions
            2145533,    // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the ChainStateFlushed debug.log lines)
            0.006673443 // * estimated number of transactions per second after that timestamp
                        //   2145533/(1666903503-1345400356) = 0.006673443
        };*/
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        //consensus.BIP16Height = 0;
        consensus.BIP34Height = 99999999; // 293368;
        consensus.BIP34Hash = uint256S("0000000000000000000000000000000000000000000000000000000000000000"); // dummy
        // ppc original:  uint256S("00000002c0b976c7a5c9878f1cec63fb4d88d68d614aedeaf8158c42d904795e");
        consensus.powLimit =            uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 16
        consensus.bnInitialHashTarget = uint256S("00007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 17;

        // SLM specific // workaround: moved to chain.h
        //consensus.nPoWBase = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // nPoWBase(~uint256(0) >> 20);
        //consensus.nPoBBase = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // nPoBBase(~uint256(0) >> 20);

        consensus.nTargetTimespan = 6 * 60 * 60; // SLM: from Block 4258 on
        consensus.nTargetTimespanBefore4258 = 30 * 60; // SLM: until block 4257

        consensus.nStakeTargetSpacing = 90; // 10 * 60;  // 10-minute block spacing
        consensus.nTargetSpacingWorkMax = 10 * consensus.nStakeTargetSpacing; // 2-hour
        consensus.nPowTargetSpacing = consensus.nStakeTargetSpacing;
        consensus.nStakeMinAge = 60 * 60 * 24; // test net min age is 1 day // SLM too.
        consensus.nStakeMaxAge = 60 * 60 * 24 * 90; // SLM seems unchanged.
        consensus.nModifierInterval = 60 * 20; // Modifier interval: time to elapse before new modifier is computed // SLM too.
        consensus.nCoinbaseMaturity = 60; // SLM too

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        consensus.SegwitHeight = 99999999; // 394215; // TODO see above

        // consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000a39348f70f067a");  // 500000
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000100010001"); // dummy value: diff 1.
        consensus.defaultAssumeValid = uint256S("0x0000001fb0391ee881524a21acddfd07ca8a3443910cb765a1568f17b3c209bc"); // slm testnet block 1000

        // pchMessageStart[4] = { 0x4d, 0x2a, 0xe1, 0xab };
        pchMessageStart[0] = 0x4d;
        pchMessageStart[1] = 0x2a;
        pchMessageStart[2] = 0xe1;
        pchMessageStart[3] = 0xab;

        nDefaultPort = 41684; // 9903;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;

        genesis = CreateGenesisBlock(1390500425, 1390500425, 63626, 0x1f00ffff, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000d7e8a80fec4057cb6d560822705596040bf41f0ebb2465dcdf46e4c517e"));
        assert(genesis.hashMerkleRoot == uint256S("0xce86aa96a71e5c74ea535ed5f23d5b1b6ca279ad16cac3cb95e123d80027f014"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //vSeeds.emplace_back("tseed.peercoin.net");
        //vSeeds.emplace_back("tseed2.peercoin.net");
        //vSeeds.emplace_back("tseed.peercoin-library.org");
        //vSeeds.emplace_back("testseed.ppcoin.info");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111); // SLM: all unchanged from PPC
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // human readable prefix to bench32 address
        bech32_hrp = "tsl";

        // vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));
        vFixedSeeds.clear();

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {     0, uint256S("00000d7e8a80fec4057cb6d560822705596040bf41f0ebb2465dcdf46e4c517e")} // 2023 testnet genesis
                /*{     0, uint256S("0x00000001f757bb737f6596503e17cd17b0658ce630cc727c0cca81aec47c9f06")}, // PPC testnet checkpoints
                { 19080, uint256S("0xb054d63d41852d71b611eaa8eca37d9fddca69b5013cf0966d453402ec8005ce")},
                { 30583, uint256S("0x5179c0c496b5d25ab81ffe14273ea6928c6ff81c0a0d6a83b5d7d41d64886300")},
                { 99999, uint256S("0xa7b03b14b8673683d972ab81775f3e85fea4fe689874b5956183466535dc651c")},
                {219999, uint256S("0x0691bb86c92762c5c4c5a3723585ebeb7ec59310bbb0bdb6666551ab24ad919e")},
                {336000, uint256S("0xf07adf61615c529f7c282b858d13d3e037b197324cb12e0669c461947494c4e3")},
                {372751, uint256S("0x000000000000148db599b217c117b5104f5043c55f6ca2a8a065d9fab9f9bba1")},
                {382019, uint256S("0x3ab75769d7957d9bf0857b5019d0a0e41044fa9ecf30b2f9c32aa457b0864ce5")},
                {408500, uint256S("0x1636ac08b073d26b28fa40243d58dd5deb215752efe094c92c61998e4e9baf3f")},
                {412691, uint256S("0x0e20318be88f07f521453435b37cfc516c3de07264a78ed7170985a1126126ab")},
                {441299, uint256S("0x4091d0836a37c50ceee876000ac0cb251fd10031dab901d2c0677cd86283096e")},
                {442735, uint256S("0x1b83b33894d51be0b8b323bfab093f638915236e0e40ba3b52bb33fdbc4053cd")},*/
            }
        };

        m_assumeutxo_data = MapAssumeutxo{
            // TODO to be specified in a future patch.
        };

        chainTxData = ChainTxData{
            // Data as of block 00000079bf04c6ef23a0a24a7ad7ffff984ab4e1d396d261cfa958203b2bf290 (height 140000)
            // TODO: estimated, see above.
            1685056582, // * UNIX timestamp of last known number of transactions
            168000,     // * total number of transactions between genesis and that timestamp

                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.013 // * estimated number of transactions per second after that timestamp
                        //   980877/(1664282408-1346029522) = 0.003082068

        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325). // TODO signet & regtest not implemented for SLM!
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const ArgsManager& args) {
        std::vector<uint8_t> bin;
        vSeeds.clear();

        if (!args.IsArgSet("-signetchallenge")) {
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            vSeeds.emplace_back("seed.signet.bitcoin.sprovoost.nl.");

            // Hardcoded nodes can be removed once there are more DNS seeds
            vSeeds.emplace_back("178.128.221.177");
            vSeeds.emplace_back("v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion:38333");

            consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000de26b0e471");
            consensus.defaultAssumeValid = uint256S("0x00000112852484b5fe3451572368f93cfd2723279af3464e478aee35115256ef"); // 78788
            m_assumed_blockchain_size = 1;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 4096 0000003d9144c56ac110ae04a0c271a0acce2f14f426b39fdf0d938c96d2eb09
                /* nTime    */ 1645631279,
                /* nTxCount */ 1257429,
                /* dTxRate  */ 0.1389638742514995,
            };
        } else {
            const auto signet_challenge = args.GetArgs("-signetchallenge");
            if (signet_challenge.size() != 1) {
                throw std::runtime_error(strprintf("%s: -signetchallenge cannot be multiple values.", __func__));
            }
            bin = ParseHex(signet_challenge[0]);

            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", signet_challenge[0]);
        }

        if (args.IsArgSet("-signetseednode")) {
            vSeeds = args.GetArgs("-signetseednode");
        }

        strNetworkID = CBaseChainParams::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.BIP16Exception = uint256{};
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
//        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("00000377ae000000000000000000000000000000000000000000000000000000");
/*
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay
*/
        // message start is defined as the first 4 bytes of the sha256d of the block script
        CHashWriter h(SER_DISK, 0);
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        memcpy(pchMessageStart, hash.begin(), 4);

        nDefaultPort = 38333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1345083810, 1345090000, 122894938, 0x1d0fffff, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        // disabled temporarily, assertions not working in SLM tests! (cannot work because some params were changed)
        //assert(consensus.hashGenesisBlock == uint256S("0x00000001f757bb737f6596503e17cd17b0658ce630cc727c0cca81aec47c9f06"));
        //assert(genesis.hashMerkleRoot == uint256S("0x3c2d8f85fab4d17aac558cc648a1a58acff0de6deb890c29985690052c5993c2"));

        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */

class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.powLimit =            uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 28;
        consensus.bnInitialHashTarget = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 29;

        consensus.nTargetTimespan = 7 * 24 * 60 * 60; // two weeks
        consensus.nStakeTargetSpacing = 10 * 60; // 10-minute block spacing
        consensus.nTargetSpacingWorkMax = 12 * consensus.nStakeTargetSpacing; // 2-hour
        consensus.nPowTargetSpacing = consensus.nStakeTargetSpacing;

        consensus.nStakeMinAge = 60 * 60 * 24; // test net min age is 1 day
        consensus.nStakeMaxAge = 60 * 60 * 24 * 90;
        consensus.nModifierInterval = 60 * 20; // Modifier interval: time to elapse before new modifier is computed
        consensus.nCoinbaseMaturity = 60;

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
/*
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay
*/
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xcb;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xef;
        nDefaultPort = 9903;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;

        genesis = CreateGenesisBlock(1345083810, 1345090000, 122894938, 0x1d0fffff, 1, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        // assertions disabled temporarily for SLM test
        //assert(consensus.hashGenesisBlock == uint256S("0x00000001f757bb737f6596503e17cd17b0658ce630cc727c0cca81aec47c9f06"));
        //assert(genesis.hashMerkleRoot == uint256S("0x3c2d8f85fab4d17aac558cc648a1a58acff0de6deb890c29985690052c5993c2"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        m_is_test_chain = true;
        m_is_mockable_chain = true;
        checkpointData = {
            {
                {0, uint256S("0x00000001f757bb737f6596503e17cd17b0658ce630cc727c0cca81aec47c9f06")},
            }
        };

        m_assumeutxo_data = MapAssumeutxo{
            {
                110,
                {AssumeutxoHash{uint256S("0x1ebbf5850204c0bdb15bf030f47c7fe91d45c44c712697e4509ba67adb01c618")}, 110},
            },
            {
                200,
                {AssumeutxoHash{uint256S("0x51c8d11d8b5c1de51543c579736e786aa2736206d1e11e627568029ce092cf62")}, 200},
            },
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "pcrt";
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        //fMineBlocksOnDemand = true;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

static void MaybeUpdateHeights(const ArgsManager& args, Consensus::Params& consensus)
{
    for (const std::string& arg : args.GetArgs("-testactivationheight")) {
        const auto found{arg.find('@')};
        if (found == std::string::npos) {
            throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
        }
        const auto name{arg.substr(0, found)};
        const auto value{arg.substr(found + 1)};
        int32_t height;
        if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
        }
        if (name == "segwit") {
            consensus.SegwitHeight = int{height};
        } else if (name == "bip34") {
            consensus.BIP34Height = int{height};
        } else if (name == "dersig") {
            //consensus.BIP66Height = int{height};
        } else if (name == "cltv") {
            //consensus.BIP65Height = int{height};
        } else if (name == "csv") {
            consensus.CSVHeight = int{height};
        } else {
            throw std::runtime_error(strprintf("Invalid name (%s) for -testactivationheight=name@height.", arg));
        }
    }
}

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    MaybeUpdateHeights(args, consensus);
 }

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams());
    } else if (chain == CBaseChainParams::TESTNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    } else if (chain == CBaseChainParams::SIGNET) {
        return std::unique_ptr<CChainParams>(new SigNetParams(args));
    } else if (chain == CBaseChainParams::REGTEST) {
        return std::unique_ptr<CChainParams>(new CRegTestParams(args));
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(gArgs, network);
}
