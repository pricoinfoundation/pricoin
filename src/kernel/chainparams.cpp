// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <arith_uint256.h>
#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <pow/randomx_pricoin.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/log.h>
#include <util/strencodings.h>

#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string>
#include <string_view>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <map>
#include <span>
#include <utility>

using namespace util::hex_literals;

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

// Pricoin: brute-force nNonce until the genesis block's RandomX hash
// satisfies its declared nBits target. Used once at chain deploy time;
// the resulting (nNonce, hashGenesisBlock, hashMerkleRoot) is hardcoded
// into the params asserts below. Triggered by env var
// PRICOIN_MINE_GENESIS=1 — without it, the daemon assumes the asserts
// are accurate and skips mining.
namespace {
void MineGenesisIfRequested(CBlock& genesis, std::string_view chain_name, const uint256& pow_limit)
{
    if (std::getenv("PRICOIN_MINE_GENESIS") == nullptr) return;

    arith_uint256 target;
    bool fNegative, fOverflow;
    target.SetCompact(genesis.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || target == 0) {
        LogInfo("Pricoin genesis miner: invalid nBits %08x for %s",
                 genesis.nBits, chain_name);
        std::exit(1);
    }
    // Catch the specific footgun where `nBits` decodes to a target above the
    // chain's powLimit: the miner happily finds a hash under that target, but
    // CheckProofOfWork rejects every such block at validation. Bail with a
    // loud error so the operator picks a stricter nBits or relaxes powLimit.
    if (target > UintToArith256(pow_limit)) {
        std::fprintf(stderr,
            "Pricoin genesis miner: target derived from nBits=%08x exceeds "
            "consensus.powLimit for %s; CheckProofOfWork would reject every "
            "mined block. Tighten nBits or relax powLimit.\n",
            genesis.nBits, std::string(chain_name).c_str());
        std::exit(1);
    }

    LogInfo("Pricoin genesis miner: searching nonce for %s (nTime=%u nBits=%08x)",
             chain_name, genesis.nTime, genesis.nBits);
    genesis.nNonce = 0;
    while (UintToArith256(pricoin::randomx::GetPoWHashOfHeader(genesis)) > target) {
        if (genesis.nNonce == std::numeric_limits<uint32_t>::max()) {
            LogInfo("Pricoin genesis miner: nonce space exhausted for %s; bump nTime",
                     chain_name);
            std::exit(1);
        }
        ++genesis.nNonce;
    }
    std::fprintf(stderr,
        "PRICOIN_GENESIS chain=%s nNonce=%u hashGenesisBlock=%s hashMerkleRoot=%s\n",
        std::string(chain_name).c_str(), genesis.nNonce,
        genesis.GetHash().ToString().c_str(),
        genesis.hashMerkleRoot.ToString().c_str());
    std::fflush(stderr);
}

// Bypass the genesis-hash asserts when we're in mining mode (so we don't
// abort after the first chain's assert fails — we want the miner to run for
// every chain and print all results in one go).
bool ShouldSkipGenesisAssert()
{
    return std::getenv("PRICOIN_MINE_GENESIS") != nullptr;
}
} // namespace

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256{"00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"}, SCRIPT_VERIFY_NONE);
        consensus.script_flag_exceptions.emplace( // Taproot exception
            uint256{"0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"}, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
        // Pricoin: all soft forks active from height 1. v4 confidential txs
        // sign their transparent input via SegWit (P2WPKH witness), so SegWit
        // MUST be active for v4 mempool txs to land in a block — otherwise
        // CheckWitnessMalleation rejects the candidate as "unexpected-witness".
        // Bitcoin's historic activation heights make no sense for a fresh
        // chain anyway.
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 0;
        // Pricoin: brand-new chain with a small initial network. We start with
        // the maximum-permissive limit (regtest-style `7fff…`) so the genesis
        // can be mined cheaply and difficulty retargeting can pull nBits up
        // from there as real hashrate arrives. This is a deliberate launch
        // choice for an experimental fork — Bitcoin-mainnet's much tighter
        // limit (`00000000ffff…`) wouldn't allow the easy launch nBits.
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 43200; // 12 hours (Pricoin: 288 blocks per retarget at 150s spacing)
        consensus.nPowTargetSpacing = 150; // 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1815; // 90%
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 2016;

        // Pricoin: brand-new chain — no accumulated work yet, no assume-valid
        // checkpoint. Leaving these at Bitcoin's mainnet values gates header
        // sync at the network layer (peers below the threshold are ignored
        // by headers-presync), so fresh nodes can never sync from each other.
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xc3;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 9543;
        nPruneAfterHeight = 100000;
        // Pricoin: brand-new chain. Update these as the network grows; they
        // only drive the disk-space warning at startup and the GUI's
        // "approximate size" hint, not consensus.
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        // Pricoin mainnet genesis.
        genesis = CreateGenesisBlock(
            "Pricoin main 2026/04/29 confidential amounts stealth ring",
            CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG,
            /*nTime=*/1777420800, /*nNonce=*/0, /*nBits=*/0x207fffff, /*nVersion=*/1, 50 * COIN);
        MineGenesisIfRequested(genesis, "main", consensus.powLimit);
        consensus.hashGenesisBlock = genesis.GetHash();
        if (!ShouldSkipGenesisAssert()) {
            assert(consensus.hashGenesisBlock == uint256{"24e422e08dde75fe0f0016d9170bb6724d6970dc6df6adbcdd220225d06a827f"});
            assert(genesis.hashMerkleRoot == uint256{"bf3f2fce2d30fbd874bd703fd5502c2abce1dde9aac21d871aaea9febb16db8b"});
        }

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        // Pricoin mainnet DNS seeds. Each entry should resolve to an A/AAAA
        // record of a long-running node accepting incoming connections on
        // nDefaultPort (9543).
        vSeeds.emplace_back("peer1.pricoin.io.");
        vSeeds.emplace_back("peer2.pricoin.io.");
        vSeeds.emplace_back("peer3.pricoin.io.");
        vSeeds.emplace_back("peer4.pricoin.io.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "pric";

        // Pricoin: no embedded seed list yet — rely on DNS seeds above. The
        // Bitcoin chainparams_seed_main blob points at Bitcoin nodes that
        // wouldn't respond on Pricoin's port/magic.
        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data = {
            {
                .height = 840'000,
                .hash_serialized = AssumeutxoHash{uint256{"a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"}},
                .m_chain_tx_count = 991032194,
                .blockhash = uint256{"0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"},
            },
            {
                .height = 880'000,
                .hash_serialized = AssumeutxoHash{uint256{"dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9"}},
                .m_chain_tx_count = 1145604538,
                .blockhash = uint256{"000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"},
            },
            {
                .height = 910'000,
                .hash_serialized = AssumeutxoHash{uint256{"4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"}},
                .m_chain_tx_count = 1226586151,
                .blockhash = uint256{"0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"},
            },
            {
                .height = 935'000,
                .hash_serialized = AssumeutxoHash{uint256{"e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050"}},
                .m_chain_tx_count = 1305397408,
                .blockhash = uint256{"0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac
            .nTime    = 1772055173,
            .tx_count = 1315805869,
            .dTxRate  = 5.40111006496122,
        };

        // Generated by headerssync-params.py on 2026-02-25.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 641,
            .redownload_buffer_size = 15218, // 15218/641 = ~23.7 commitments
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256{"00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"}, SCRIPT_VERIFY_NONE);
        // Pricoin: see CMainParams — all soft forks active from height 1.
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 0;
        // Pricoin: see CMainParams — relaxed to allow nBits=0x207fffff genesis.
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 43200; // 12 hours
        consensus.nPowTargetSpacing = 150; // 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1512; // 75%
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 2016;

        // Pricoin: brand-new chain — see CMainParams.
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0x0c;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0x0a;
        pchMessageStart[3] = 0x08;
        nDefaultPort = 19543;
        nPruneAfterHeight = 1000;
        // Pricoin: brand-new chain — see CMainParams.
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        // Pricoin testnet3 genesis. Same low-difficulty target as mainnet
        // genesis under our RandomX scheme; DAA takes over after.
        genesis = CreateGenesisBlock(
            "Pricoin test 2026/04/29 confidential amounts stealth ring",
            CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG,
            /*nTime=*/1777420800, /*nNonce=*/6, /*nBits=*/0x207fffff, /*nVersion=*/1, 50 * COIN);
        MineGenesisIfRequested(genesis, "test", consensus.powLimit);
        consensus.hashGenesisBlock = genesis.GetHash();
        if (!ShouldSkipGenesisAssert()) {
            assert(consensus.hashGenesisBlock == uint256{"5570e9dc66c242b7c0d5c5acd42b5ff811fdee0618adfad1860b7df4ade1048a"});
            assert(genesis.hashMerkleRoot == uint256{"071164c03d7fc7815728ea793a52e9f02005f15a9e3ab57c1b9ead7a0948d06f"});
        }

        vFixedSeeds.clear();
        vSeeds.clear();
        // Pricoin: no testnet DNS seeds defined yet.

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tpric";

        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data = {
            {
                .height = 2'500'000,
                .hash_serialized = AssumeutxoHash{uint256{"f841584909f68e47897952345234e37fcd9128cd818f41ee6c3ca68db8071be7"}},
                .m_chain_tx_count = 66484552,
                .blockhash = uint256{"0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f"},
            },
            {
                .height = 4'840'000,
                .hash_serialized = AssumeutxoHash{uint256{"ce6bb677bb2ee9789c4a1c9d73e6683c53fc20e8fdbedbdaaf468982a0c8db2a"}},
                .m_chain_tx_count = 536078574,
                .blockhash = uint256{"00000000000000f4971a7fb37fbdff89315b69a2e1920c467654a382f0d64786"},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4
            .nTime    = 1772051651,
            .tx_count = 536108416,
            .dTxRate  = 0.02691479016257117,
        };

        // Generated by headerssync-params.py on 2026-02-25.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 673,
            .redownload_buffer_size = 14460, // 14460/673 = ~21.5 commitments
        };
    }
};

/**
 * Testnet (v4): public test network which is reset from time to time.
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        m_chain_type = ChainType::TESTNET4;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 0;
        // Pricoin: see CMainParams — relaxed to allow nBits=0x207fffff genesis.
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 43200; // 12 hours
        consensus.nPowTargetSpacing = 150; // 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1512; // 75%
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 2016;

        // Pricoin: brand-new chain — see CMainParams.
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0x1d;
        pchMessageStart[1] = 0x17;
        pchMessageStart[2] = 0x40;
        pchMessageStart[3] = 0x29;
        nDefaultPort = 49543;
        nPruneAfterHeight = 1000;
        // Pricoin: brand-new chain — see CMainParams.
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        // Pricoin testnet4 genesis.
        genesis = CreateGenesisBlock(
            "Pricoin testnet4 2026/04/29 confidential amounts stealth ring",
            CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG,
            /*nTime=*/1777420800, /*nNonce=*/0, /*nBits=*/0x207fffff, /*nVersion=*/1, 50 * COIN);
        MineGenesisIfRequested(genesis, "testnet4", consensus.powLimit);
        consensus.hashGenesisBlock = genesis.GetHash();
        if (!ShouldSkipGenesisAssert()) {
            assert(consensus.hashGenesisBlock == uint256{"095b0cf5917cfa4ad80e8d616d82537f2fadcc15a6157f1569d9b0db8ca92216"});
            assert(genesis.hashMerkleRoot == uint256{"ca62b62b09c62bb3790c2bf4917040f46052b9a194b13ef11da6a963526b7c34"});
        }

        vFixedSeeds.clear();
        vSeeds.clear();
        // Pricoin: no testnet4 DNS seeds defined yet.

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tpric";

        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data = {
            {
                .height = 90'000,
                .hash_serialized = AssumeutxoHash{uint256{"784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5"}},
                .m_chain_tx_count = 11347043,
                .blockhash = uint256{"0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b"},
            },
            {
                .height = 120'000,
                .hash_serialized = AssumeutxoHash{uint256{"10b05d05ad468d0971162e1b222a4aa66caca89da2bb2a93f8f37fb29c4794b0"}},
                .m_chain_tx_count = 14141057,
                .blockhash = uint256{"000000000bd2317e51b3c5794981c35ba894ce27d3e772d5c39ecd9cbce01dc8"},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a
            .nTime    = 1772013387,
            .tx_count = 14191421,
            .dTxRate  = 0.01848579579528412,
        };

        // Generated by headerssync-params.py on 2026-02-25.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 606,
            .redownload_buffer_size = 16092, // 16092/606 = ~26.6 commitments
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vFixedSeeds.clear();
        vSeeds.clear();

        if (!options.challenge) {
            bin = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"_hex_v_u8;
            // Pricoin: no signet DNS seeds defined yet.
            vFixedSeeds.clear();

            // Pricoin: brand-new chain — see CMainParams.
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            // Pricoin: brand-new chain — see CMainParams.
            m_assumed_blockchain_size = 1;
            m_assumed_chain_state_size = 1;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 4096 00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329
                .nTime    = 1772055248,
                .tx_count = 28676833,
                .dTxRate  = 0.06736623436338929,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogInfo("Signet with challenge %s", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nPowTargetTimespan = 43200; // 12 hours
        consensus.nPowTargetSpacing = 150; // 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.MinBIP9WarningHeight = 0;
        // Pricoin: see CMainParams — relaxed to allow nBits=0x207fffff genesis.
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1815; // 90%
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 2016;

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 39543;
        nPruneAfterHeight = 1000;

        // Pricoin signet genesis.
        genesis = CreateGenesisBlock(
            "Pricoin signet 2026/04/29 confidential amounts stealth ring",
            CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG,
            /*nTime=*/1777420800, /*nNonce=*/0, /*nBits=*/0x207fffff, /*nVersion=*/1, 50 * COIN);
        MineGenesisIfRequested(genesis, "signet", consensus.powLimit);
        consensus.hashGenesisBlock = genesis.GetHash();
        if (!ShouldSkipGenesisAssert()) {
            assert(consensus.hashGenesisBlock == uint256{"c1d41765c6c996f9241a8934f48b3e3058266f84754fe479fcd26f3d6fa9f6a4"});
            assert(genesis.hashMerkleRoot == uint256{"e817b7fdfab9f0c54cbbd85870c9eca4d97887953d5b6e0628863ca39fda9cf4"});
        }

        m_assumeutxo_data = {
            {
                .height = 160'000,
                .hash_serialized = AssumeutxoHash{uint256{"fe0a44309b74d6b5883d246cb419c6221bcccf0b308c9b59b7d70783dbdf928a"}},
                .m_chain_tx_count = 2289496,
                .blockhash = uint256{"0000003ca3c99aff040f2563c2ad8f8ec88bd0fd6b8f0895cfaf1ef90353a62c"},
            },
            {
                .height = 290'000,
                .hash_serialized = AssumeutxoHash{uint256{"97267e000b4b876800167e71b9123f1529d13b14308abec2888bbd2160d14545"}},
                .m_chain_tx_count = 28547497,
                .blockhash = uint256{"0000000577f2741bb30cd9d39d6d71b023afbeb9764f6260786a97969d5c9ac0"},
            }
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tpric";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        // Generated by headerssync-params.py on 2026-02-25.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 620,
            .redownload_buffer_size = 15724, // 15724/620 = ~25.4 commitments
        };
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 150; // 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = opts.enforce_bip94;
        consensus.fPowNoRetargeting = true;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 108; // 75%
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xdb;
        nDefaultPort = 19544;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        // Pricoin regtest genesis.
        genesis = CreateGenesisBlock(
            "Pricoin regtest 2026/04/29 confidential amounts stealth ring",
            CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG,
            /*nTime=*/1777420800, /*nNonce=*/0, /*nBits=*/0x207fffff, /*nVersion=*/1, 50 * COIN);
        MineGenesisIfRequested(genesis, "regtest", consensus.powLimit);
        consensus.hashGenesisBlock = genesis.GetHash();
        if (!ShouldSkipGenesisAssert()) {
            assert(consensus.hashGenesisBlock == uint256{"445625a5f05fc13ea721fdefb34390a480d23ad71ea84da4bd25d33288d35588"});
            assert(genesis.hashMerkleRoot == uint256{"59944c60f655b87306f460e622f053f1dd245b56b91f14fcab0a0dfc16ec4d81"});
        }

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        m_assumeutxo_data = {
            {   // For use by unit tests
                .height = 110,
                .hash_serialized = AssumeutxoHash{uint256{"b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327"}},
                .m_chain_tx_count = 111,
                .blockhash = uint256{"6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397"},
            },
            {
                // For use by fuzz target src/test/fuzz/utxo_snapshot.cpp
                .height = 200,
                .hash_serialized = AssumeutxoHash{uint256{"17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a"}},
                .m_chain_tx_count = 201,
                .blockhash = uint256{"385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9"},
            },
            {
                // For use by test/functional/feature_assumeutxo.py and test/functional/tool_bitcoin_chainstate.py
                .height = 299,
                .hash_serialized = AssumeutxoHash{uint256{"d2b051ff5e8eef46520350776f4100dd710a63447a8e01d917e92e79751a63e2"}},
                .m_chain_tx_count = 334,
                .blockhash = uint256{"7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2"},
            },
        };

        chainTxData = ChainTxData{
            .nTime = 0,
            .tx_count = 0,
            .dTxRate = 0.001, // Set a non-zero rate to make it testable
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "pricrt";

        // Copied from Testnet4.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 275,
            .redownload_buffer_size = 7017, // 7017/275 = ~25.5 commitments
        };
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet4()
{
    return std::make_unique<const CTestNet4Params>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto testnet4_msg = CChainParams::TestNet4()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet_msg)) {
        return ChainType::TESTNET;
    } else if (std::ranges::equal(message, testnet4_msg)) {
        return ChainType::TESTNET4;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    } else if (std::ranges::equal(message, signet_msg)) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}
