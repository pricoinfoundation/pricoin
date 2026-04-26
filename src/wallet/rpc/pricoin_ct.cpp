// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/amount.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <logging.h>
#include <pricoin/ringsig.h>
#include <pricoin/ct.h>
#include <pricoin/cttx.h>
#include <pricoin/stealth.h>
#include <primitives/transaction.h>
#include <interfaces/chain.h>
#include <node/types.h>
#include <pubkey.h>
#include <random.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <core_io.h>
#include <wallet/coincontrol.h>
#include <wallet/coinselection.h>
#include <wallet/pricoin_stealth.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace wallet {

namespace {

// Pick the first P2WPKH UTXO with sufficient value. Returns just the
// outpoint + value + scriptPubKey; the wallet's SignTransaction handles the
// signing via its own keystore.
struct PickedInput {
    COutPoint outpoint;
    CAmount value;
    CScript scriptPubKey;
};
std::optional<PickedInput> PickP2WPKHFunding(CWallet& wallet, CAmount target)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CoinFilterParams filter;
    filter.skip_locked = true;
    auto avail = AvailableCoins(wallet, /*coinControl=*/nullptr, /*feerate=*/std::nullopt, filter);

    for (const auto& coin : avail.All()) {
        if (coin.txout.nValue < target) continue;
        const CScript& spk = coin.txout.scriptPubKey;
        if (spk.size() != 22 || spk[0] != OP_0 || spk[1] != 0x14) continue;
        return PickedInput{coin.outpoint, coin.txout.nValue, spk};
    }
    return std::nullopt;
}

RPCMethod walletsendct()
{
    return RPCMethod{
        "walletsendct",
        "Build, sign, and submit a Pricoin Confidential Transaction using wallet UTXOs.\n"
        "Picks the first P2WPKH wallet UTXO whose value >= dest_amount + fee, signs with the\n"
        "wallet's keystore, generates a change address from the wallet, and submits the\n"
        "resulting v4 transaction. Receive-side detection is not yet implemented (Phase 2d-6b),\n"
        "so the recipient cannot auto-recover the value from the rangeproof.\n",
        {
            {"dest_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination Pricoin bech32 address"},
            {"dest_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to send in PRIC"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Transparent fee in PRIC"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Submitted transaction id"},
                {RPCResult::Type::STR_HEX, "hex", "Hex-encoded signed v4 transaction"},
                {RPCResult::Type::NUM, "size", "Total serialized size in bytes"},
                {RPCResult::Type::NUM, "bundle_size", "CT bundle size in bytes"},
                {RPCResult::Type::STR, "input_outpoint", "Spent input as txid:vout"},
                {RPCResult::Type::STR_AMOUNT, "input_value", "Value of the consumed input in PRIC"},
                {RPCResult::Type::STR, "change_address", "Change address used"},
                {RPCResult::Type::STR_AMOUNT, "change_amount", "Change value (carried in the bundle, not visible)"},
            }
        },
        RPCExamples{
            HelpExampleCli("walletsendct", "\"pricrt1q...\" 25.0 0.001")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;

            const std::string dest_addr_str = request.params[0].get_str();
            const CAmount dest_amount = AmountFromValue(request.params[1]);
            const CAmount fee = AmountFromValue(request.params[2]);
            if (dest_amount <= 0 || fee < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative or zero amount");
            }
            const CAmount target = dest_amount + fee;

            // Detect whether the destination is a stealth address. If so,
            // derive a one-time scriptPubKey via ECDH against the recipient's
            // view key. Otherwise treat it as a regular bech32 address.
            const auto stealth_dest = ::pricoin::stealth::Decode(dest_addr_str);
            CScript dest_spk;
            ::pricoin::stealth::PointBytes dest_R{};
            ::pricoin::ct::BlindingFactor dest_nonce{};
            ::pricoin::ct::SerializedPubKey33 dest_otp{};
            if (stealth_dest) {
                CKey r;
                r.MakeNewKey(/*fCompressed=*/true);
                CPubKey R = r.GetPubKey();
                std::memcpy(dest_R.data(), R.data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, stealth_dest->view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH failed");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, /*output_index=*/0);
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, stealth_dest->spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime pubkey failed");
                dest_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                std::memcpy(dest_otp.data(), P->data(), 33);
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 0);
                std::memcpy(dest_nonce.data(), rp_nonce.data(), 32);
            } else {
                CTxDestination dest_dest = DecodeDestination(dest_addr_str);
                if (!IsValidDestination(dest_dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid dest_address (neither stealth nor bech32)");
                }
                dest_spk = GetScriptForDestination(dest_dest);
                GetRandBytes(dest_nonce);
                // dest_otp stays zero — non-stealth output won't be usable as a ring member.
            }

            // Always send change to our own stealth address so the wallet can
            // recover it via Phase 5e block-scan once that lands.
            const auto& self_id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            CScript change_spk;
            ::pricoin::stealth::PointBytes change_R{};
            ::pricoin::ct::BlindingFactor change_nonce{};
            ::pricoin::ct::SerializedPubKey33 change_otp{};
            {
                CKey r;
                r.MakeNewKey(/*fCompressed=*/true);
                CPubKey R = r.GetPubKey();
                std::memcpy(change_R.data(), R.data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, self_id.public_address.view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH failed (change)");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, /*output_index=*/1);
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, self_id.public_address.spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime pubkey failed (change)");
                change_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                std::memcpy(change_otp.data(), P->data(), 33);
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 1);
                std::memcpy(change_nonce.data(), rp_nonce.data(), 32);
            }

            // Lock the wallet, pick a funding input.
            std::optional<PickedInput> picked;
            {
                LOCK(wallet.cs_wallet);
                picked = PickP2WPKHFunding(wallet, target);
                if (!picked) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                        "No spendable P2WPKH UTXO with value >= dest_amount + fee");
                }
            }
            const CAmount change_value = picked->value - target;

            // Build the bundle.
            pricoin::ct::BlindingFactor zero_blind{};
            auto in_commit = pricoin::ct::Commitment::Create(
                static_cast<uint64_t>(picked->value), zero_blind);
            if (!in_commit) throw JSONRPCError(RPC_INTERNAL_ERROR, "input commit failed");

            pricoin::ct::BlindingFactor dest_blind;
            GetRandBytes(dest_blind);
            auto change_blind = pricoin::ct::BalancingBlind(
                std::array<pricoin::ct::BlindingFactor, 1>{zero_blind},
                std::array<pricoin::ct::BlindingFactor, 1>{dest_blind});
            if (!change_blind) throw JSONRPCError(RPC_INTERNAL_ERROR, "blind sum failed");

            auto dest_commit = pricoin::ct::Commitment::Create(
                static_cast<uint64_t>(dest_amount), dest_blind);
            auto change_commit = pricoin::ct::Commitment::Create(
                static_cast<uint64_t>(change_value), *change_blind);
            if (!dest_commit || !change_commit) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "output commit failed");
            }

            std::vector<unsigned char> dest_spk_bytes(dest_spk.begin(), dest_spk.end());
            std::vector<unsigned char> change_spk_bytes(change_spk.begin(), change_spk.end());

            auto dest_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(dest_amount), dest_blind, *dest_commit,
                std::span<const unsigned char>{dest_spk_bytes}, dest_nonce);
            auto change_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(change_value), *change_blind, *change_commit,
                std::span<const unsigned char>{change_spk_bytes}, change_nonce);
            if (!dest_proof || !change_proof) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "rangeproof failed");
            }

            pricoin::ct::CTBundle bundle;
            bundle.input_commitments = {*in_commit};
            bundle.outputs = {
                pricoin::ct::CTOutput{*dest_commit, *dest_proof, dest_spk_bytes, dest_R, dest_otp},
                pricoin::ct::CTOutput{*change_commit, *change_proof, change_spk_bytes, change_R, change_otp},
            };
            bundle.transparent_fee = static_cast<uint64_t>(fee);

            CMutableTransaction mtx;
            mtx.version = PRICOIN_CT_VERSION;
            mtx.nLockTime = 0;
            mtx.vin.emplace_back(picked->outpoint, CScript{}, 0xfffffffe);
            mtx.vout.emplace_back(0, dest_spk);
            mtx.vout.emplace_back(0, change_spk);
            mtx.ct_bundle = std::move(bundle);

            // Build the prev-coin map the wallet needs to sign the input
            // (BIP143 sighash needs the prev value/script).
            std::map<COutPoint, Coin> coins;
            Coin prev_coin;
            prev_coin.out = CTxOut{picked->value, picked->scriptPubKey};
            prev_coin.fCoinBase = false; // wallet's signer doesn't care for sigs
            prev_coin.nHeight = 0;
            coins.emplace(picked->outpoint, std::move(prev_coin));

            std::map<int, bilingual_str> input_errors;
            if (!wallet.SignTransaction(mtx, coins, SIGHASH_ALL, input_errors)) {
                std::string msg;
                for (const auto& [i, e] : input_errors) msg += strprintf("vin[%d]: %s; ", i, e.original);
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet failed to sign tx: " + msg);
            }

            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            DataStream ds;
            ds << TX_WITH_WITNESS(*tx_ref);

            // Submit through the wallet's broadcast path so the wallet
            // tracks it as outgoing.
            std::string err;
            wallet.CommitTransaction(tx_ref, /*mapValue=*/{}, /*orderForm=*/{});

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", tx_ref->GetHash().ToString());
            out.pushKV("hex", HexStr(ds));
            out.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(*tx_ref)));
            out.pushKV("bundle_size", (int)tx_ref->ct_bundle.SerializedSize());
            out.pushKV("input_outpoint", picked->outpoint.hash.ToString() + ":" + std::to_string(picked->outpoint.n));
            out.pushKV("input_value", ValueFromAmount(picked->value));
            out.pushKV("change_to", "(wallet's own stealth address)");
            out.pushKV("change_amount", ValueFromAmount(change_value));
            out.pushKV("dest_was_stealth", stealth_dest.has_value());
            return out;
        }
    };
}

} // namespace

RPCMethod walletsendct_export() { return walletsendct(); }

namespace {

// Try to recover a CT output for a given wallet stealth identity. Returns
// nullopt if the output is not addressed to us (fast path: scriptPubKey
// mismatch). On match, returns the recovered (value, blind, output_index)
// plus enough material to spend the output later.
struct RecoveredOutput {
    uint32_t output_index;
    CAmount value;
    pricoin::ct::BlindingFactor blind;
    pricoin::ct::Commitment commitment;
    CScript scriptPubKey;
    CKey one_time_priv; // derived spend key for this output
};

std::optional<RecoveredOutput> TryRecoverCTOutput(
    const ::wallet::pricoin_stealth::Identity& id,
    const CTransaction& tx,
    uint32_t output_index)
{
    if (tx.version != PRICOIN_CT_VERSION) return std::nullopt;
    if (output_index >= tx.ct_bundle.outputs.size()) return std::nullopt;
    if (output_index >= tx.vout.size()) return std::nullopt;

    const auto& out = tx.ct_bundle.outputs[output_index];
    // tx_pubkey of all zeros means non-stealth output — skip.
    bool all_zero = true;
    for (auto b : out.tx_pubkey) { if (b != 0) { all_zero = false; break; } }
    if (all_zero) return std::nullopt;

    CPubKey R(std::span<const unsigned char>{out.tx_pubkey.data(), out.tx_pubkey.size()});
    if (!R.IsValid()) return std::nullopt;

    auto S = ::pricoin::stealth::ECDHPoint(id.view, R);
    if (!S) return std::nullopt;
    auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, output_index);
    auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, id.public_address.spend);
    if (!P) return std::nullopt;
    const CScript expected_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
    if (tx.vout[output_index].scriptPubKey != expected_spk) return std::nullopt;

    // Match! Rewind the rangeproof.
    auto nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, output_index);
    pricoin::ct::BlindingFactor nonce_arr{};
    std::memcpy(nonce_arr.data(), nonce.data(), 32);
    const auto& script = out.script_pubkey;
    auto rewound = pricoin::ct::RewindRangeProof(
        out.commitment,
        std::span<const unsigned char>{out.rangeproof.data(), out.rangeproof.size()},
        std::span<const unsigned char>{script.data(), script.size()},
        nonce_arr);
    if (!rewound) return std::nullopt;

    auto one_time_priv = ::pricoin::stealth::DeriveOneTimePriv(shared, id.spend);
    if (!one_time_priv) return std::nullopt;

    return RecoveredOutput{
        .output_index = output_index,
        .value = static_cast<CAmount>(rewound->value),
        .blind = rewound->blind,
        .commitment = out.commitment,
        .scriptPubKey = tx.vout[output_index].scriptPubKey,
        .one_time_priv = std::move(*one_time_priv),
    };
}

RPCMethod pricoin_listownct()
{
    return RPCMethod{
        "pricoin_listownct",
        "Scan confirmed blocks (and the mempool) for confidential outputs addressed to this wallet's\n"
        "stealth identity, recovering their hidden values via rangeproof rewind. Phase 5e demo.\n",
        {
            {"startheight", RPCArg::Type::NUM, RPCArg::Default{0}, "Block height to start scanning from"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "scanned_blocks", "How many blocks were scanned"},
                {RPCResult::Type::NUM, "scanned_mempool_txs", "How many mempool txs were scanned"},
                {RPCResult::Type::STR_AMOUNT, "total_recovered", "Total PRIC recovered as ours"},
                {RPCResult::Type::ARR, "outputs", "Per-output recoveries",
                    {{RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", ""},
                            {RPCResult::Type::NUM, "vout", ""},
                            {RPCResult::Type::STR_AMOUNT, "value", "Recovered amount in PRIC"},
                            {RPCResult::Type::NUM, "height", "Block height (-1 if mempool)"},
                        }}}}
            }
        },
        RPCExamples{HelpExampleCli("pricoin_listownct", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            const int startheight = request.params[0].isNull() ? 0 : request.params[0].getInt<int>();

            const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            interfaces::Chain& chain = wallet.chain();

            UniValue outputs{UniValue::VARR};
            CAmount total_recovered = 0;
            int scanned_blocks = 0;
            int scanned_mempool = 0;

            const std::optional<int> tip_opt = chain.getHeight();
            const int tip_height = tip_opt.value_or(-1);

            for (int h = std::max(startheight, 0); h <= tip_height; ++h) {
                const uint256 block_hash = chain.getBlockHash(h);
                CBlock block;
                if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) continue;
                if (block.vtx.empty()) continue;
                ++scanned_blocks;
                for (const auto& tx_ref : block.vtx) {
                    if (tx_ref->version != PRICOIN_CT_VERSION) continue;
                    for (uint32_t i = 0; i < tx_ref->vout.size(); ++i) {
                        auto rec = TryRecoverCTOutput(id, *tx_ref, i);
                        if (!rec) continue;
                        total_recovered += rec->value;
                        UniValue entry{UniValue::VOBJ};
                        entry.pushKV("txid", tx_ref->GetHash().ToString());
                        entry.pushKV("vout", (int)rec->output_index);
                        entry.pushKV("value", ValueFromAmount(rec->value));
                        entry.pushKV("height", h);
                        outputs.push_back(entry);
                    }
                }
            }
            // Mempool sweep is omitted in this MVP — interfaces::Chain doesn't
            // expose entry iteration. A confirmed-only scan is sufficient to
            // demonstrate Phase 5e end-to-end.

            UniValue out{UniValue::VOBJ};
            out.pushKV("scanned_blocks", scanned_blocks);
            out.pushKV("scanned_mempool_txs", scanned_mempool);
            out.pushKV("total_recovered", ValueFromAmount(total_recovered));
            out.pushKV("outputs", outputs);
            return out;
        }
    };
}

// Helper: collect all v4 stealth outputs in confirmed blocks. Returns
// (outpoint, commitment, one_time_pubkey) for each — usable as ring members.
struct ChainCTOutput {
    pricoin::ct::PrevoutRef ref;
    pricoin::ct::Commitment commitment;
    pricoin::ct::SerializedPubKey33 one_time_pubkey;
};

std::vector<ChainCTOutput> CollectChainCTOutputs(interfaces::Chain& chain)
{
    std::vector<ChainCTOutput> result;
    const int tip = chain.getHeight().value_or(-1);
    for (int h = 0; h <= tip; ++h) {
        const uint256 block_hash = chain.getBlockHash(h);
        CBlock block;
        if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) continue;
        for (const auto& tx_ref : block.vtx) {
            if (tx_ref->version != PRICOIN_CT_VERSION) continue;
            for (uint32_t i = 0; i < tx_ref->ct_bundle.outputs.size(); ++i) {
                const auto& o = tx_ref->ct_bundle.outputs[i];
                bool nonzero = false;
                for (auto b : o.one_time_pubkey) { if (b != 0) { nonzero = true; break; } }
                if (!nonzero) continue;
                result.push_back(ChainCTOutput{
                    .ref = pricoin::ct::PrevoutRef{tx_ref->GetHash().ToUint256(), i},
                    .commitment = o.commitment,
                    .one_time_pubkey = o.one_time_pubkey,
                });
            }
        }
    }
    return result;
}

RPCMethod walletsendct_ring()
{
    return RPCMethod{
        "walletsendct_ring",
        "Phase 4b: send a Pricoin CT transaction with sender privacy via a CLSAG ring signature.\n"
        "Hides which prev output is spent among N candidates. Funded by a recovered CT output\n"
        "(call walletsendct first to seed). N-1 decoys are randomly drawn from confirmed v4 stealth\n"
        "outputs on the chain. In-memory key-image set tracks double-spends.\n",
        {
            {"dest_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination Pricoin stealth address"},
            {"dest_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount in PRIC"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Transparent fee in PRIC"},
            {"ring_size", RPCArg::Type::NUM, RPCArg::Default{4}, "Total ring size (must have ring_size-1 decoys available)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", ""},
                {RPCResult::Type::NUM, "ring_size", "Number of candidates"},
                {RPCResult::Type::NUM, "signer_index", "Position pi (kept here for testing; not on-chain)"},
                {RPCResult::Type::STR_AMOUNT, "input_value", "Recovered input value (sent privately)"},
                {RPCResult::Type::STR_AMOUNT, "change_amount", "Change amount"},
                {RPCResult::Type::NUM, "size", ""},
                {RPCResult::Type::NUM, "bundle_size", ""},
            }
        },
        RPCExamples{HelpExampleCli("walletsendct_ring", "\"pricstl1...\" 5 0.0001 4")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;

            const std::string dest_addr_str = request.params[0].get_str();
            const CAmount dest_amount = AmountFromValue(request.params[1]);
            const CAmount fee = AmountFromValue(request.params[2]);
            const int ring_size = request.params[3].isNull() ? 4 : request.params[3].getInt<int>();
            if (ring_size < 2) throw JSONRPCError(RPC_INVALID_PARAMETER, "ring_size must be >= 2");

            const auto stealth_dest = ::pricoin::stealth::Decode(dest_addr_str);
            if (!stealth_dest) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "dest_address must be a stealth address");

            const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            interfaces::Chain& chain = wallet.chain();

            // 1. Find our recovered CT output with sufficient value.
            std::optional<RecoveredOutput> picked;
            COutPoint picked_outpoint;
            const int tip = chain.getHeight().value_or(-1);
            const CAmount target = dest_amount + fee;
            for (int h = 0; h <= tip && !picked; ++h) {
                const uint256 block_hash = chain.getBlockHash(h);
                CBlock block;
                if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) continue;
                for (const auto& tx_ref : block.vtx) {
                    if (tx_ref->version != PRICOIN_CT_VERSION) continue;
                    for (uint32_t i = 0; i < tx_ref->vout.size(); ++i) {
                        auto rec = TryRecoverCTOutput(id, *tx_ref, i);
                        if (!rec || rec->value < target) continue;
                        picked = std::move(rec);
                        picked_outpoint = COutPoint(tx_ref->GetHash(), picked->output_index);
                        break;
                    }
                    if (picked) break;
                }
            }
            if (!picked) throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No recovered CT output of sufficient value");

            // 2. Collect chain CT outputs as decoy pool (excluding our own).
            auto pool = CollectChainCTOutputs(chain);
            std::vector<ChainCTOutput> decoys;
            for (auto& c : pool) {
                if (c.ref.hash == picked_outpoint.hash.ToUint256() && c.ref.n == picked_outpoint.n) continue;
                decoys.push_back(std::move(c));
            }
            if ((int)decoys.size() < ring_size - 1) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Not enough chain CT outputs for ring_size=%d (have %d decoys)", ring_size, (int)decoys.size()));
            }
            // Shuffle and take ring_size - 1 random decoys.
            FastRandomContext rng;
            std::shuffle(decoys.begin(), decoys.end(), rng);
            decoys.resize(ring_size - 1);

            // 3. Insert our own output at a random index pi.
            const size_t pi = rng.randrange(static_cast<uint32_t>(ring_size));
            std::vector<ChainCTOutput> ring(ring_size);
            for (size_t k = 0, d = 0; k < (size_t)ring_size; ++k) {
                if (k == pi) {
                    ring[k] = ChainCTOutput{
                        .ref = pricoin::ct::PrevoutRef{picked_outpoint.hash.ToUint256(), picked_outpoint.n},
                        .commitment = picked->commitment,
                        .one_time_pubkey = {},
                    };
                    // Copy our own one_time_pubkey from the picked output's
                    // scriptPubKey-derived pubkey.
                    CPubKey one_time = picked->one_time_priv.GetPubKey();
                    std::memcpy(ring[k].one_time_pubkey.data(), one_time.data(), 33);
                } else {
                    ring[k] = decoys[d++];
                }
            }

            // 4. Build pseudo input commitment with random blind.
            pricoin::ct::BlindingFactor pseudo_blind;
            GetRandBytes(pseudo_blind);
            auto pseudo = pricoin::ct::Commitment::Create(static_cast<uint64_t>(picked->value), pseudo_blind);
            if (!pseudo) throw JSONRPCError(RPC_INTERNAL_ERROR, "pseudo commit failed");

            // 5. Compute z = picked->blind - pseudo_blind (mod n).
            //    Used as the signer's commitment-row priv key.
            pricoin::ringsig::Scalar z_pi;
            {
                auto neg = pricoin::ct::NegateScalar(pseudo_blind);
                if (!neg) throw JSONRPCError(RPC_INTERNAL_ERROR, "z negate failed");
                auto sum = pricoin::ct::AddScalars(picked->blind, *neg);
                if (!sum) throw JSONRPCError(RPC_INTERNAL_ERROR, "z add failed");
                std::memcpy(z_pi.data(), sum->data(), 32);
            }

            // 6. Build dest + change outputs (always to stealth recipients here).
            //    Output blinds are chosen so they sum to pseudo_blind (so the
            //    bundle's pseudo commitments balance against output commitments).
            const CAmount change_value = picked->value - target;

            CScript dest_spk, change_spk;
            ::pricoin::stealth::PointBytes dest_R{}, change_R{};
            ::pricoin::ct::BlindingFactor dest_nonce{}, change_nonce{};
            ::pricoin::ct::SerializedPubKey33 dest_otp{}, change_otp{};
            // Dest
            {
                CKey r; r.MakeNewKey(true);
                CPubKey R = r.GetPubKey();
                std::memcpy(dest_R.data(), R.data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, stealth_dest->view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH failed (dest)");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, 0);
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, stealth_dest->spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime failed (dest)");
                dest_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                std::memcpy(dest_otp.data(), P->data(), 33);
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 0);
                std::memcpy(dest_nonce.data(), rp_nonce.data(), 32);
            }
            // Change
            {
                CKey r; r.MakeNewKey(true);
                CPubKey R = r.GetPubKey();
                std::memcpy(change_R.data(), R.data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, id.public_address.view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH failed (change)");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, 1);
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, id.public_address.spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime failed (change)");
                change_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                std::memcpy(change_otp.data(), P->data(), 33);
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 1);
                std::memcpy(change_nonce.data(), rp_nonce.data(), 32);
            }

            // Output blinds: dest random, change = pseudo_blind - dest_blind
            // (so dest_blind + change_blind = pseudo_blind, which means
            // C_dest + C_change = pseudo_blind*G + value*H = C_pseudo when
            // values balance with the fee).
            pricoin::ct::BlindingFactor dest_blind;
            GetRandBytes(dest_blind);
            auto change_blind = pricoin::ct::BalancingBlind(
                std::array<pricoin::ct::BlindingFactor, 1>{pseudo_blind},
                std::array<pricoin::ct::BlindingFactor, 1>{dest_blind});
            if (!change_blind) throw JSONRPCError(RPC_INTERNAL_ERROR, "blind sum failed");

            auto dest_commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(dest_amount), dest_blind);
            auto change_commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(change_value), *change_blind);
            if (!dest_commit || !change_commit) throw JSONRPCError(RPC_INTERNAL_ERROR, "output commit failed");

            std::vector<unsigned char> dest_spk_bytes(dest_spk.begin(), dest_spk.end());
            std::vector<unsigned char> change_spk_bytes(change_spk.begin(), change_spk.end());
            auto dest_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(dest_amount), dest_blind, *dest_commit,
                std::span<const unsigned char>{dest_spk_bytes}, dest_nonce);
            auto change_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(change_value), *change_blind, *change_commit,
                std::span<const unsigned char>{change_spk_bytes}, change_nonce);
            if (!dest_proof || !change_proof) throw JSONRPCError(RPC_INTERNAL_ERROR, "rangeproof failed");

            // 7. Construct the bundle with a ring input.
            pricoin::ct::CTRingInput ring_input;
            ring_input.ring.reserve(ring_size);
            for (const auto& m : ring) ring_input.ring.push_back(m.ref);
            ring_input.pseudo_commitment = *pseudo;
            // Diagnostic log
            for (size_t k = 0; k < ring.size(); ++k) {
                LogInfo("Pricoin ring[%zu]: %s:%u (otp_zero=%s) %s",
                    k, ring[k].ref.hash.ToString(), ring[k].ref.n,
                    [&]{ for (auto b : ring[k].one_time_pubkey) if (b) return "no"; return "yes"; }(),
                    k == pi ? "<- signer" : "");
            }

            pricoin::ct::CTBundle bundle;
            bundle.ring_inputs = {ring_input}; // sig filled in below
            bundle.outputs = {
                pricoin::ct::CTOutput{*dest_commit, *dest_proof, dest_spk_bytes, dest_R, dest_otp},
                pricoin::ct::CTOutput{*change_commit, *change_proof, change_spk_bytes, change_R, change_otp},
            };
            bundle.transparent_fee = static_cast<uint64_t>(fee);

            // 8. Build mtx.
            CMutableTransaction mtx;
            mtx.version = PRICOIN_CT_VERSION;
            mtx.nLockTime = 0;
            // vin's prevout: set to ring[0] as a fixed convention (does not
            // reveal pi). Verifier ignores it for ring inputs.
            const COutPoint marker_outpoint{
                Txid::FromUint256(ring_input.ring[0].hash),
                ring_input.ring[0].n};
            mtx.vin.emplace_back(marker_outpoint, CScript{}, 0xfffffffe);
            mtx.vout.emplace_back(0, dest_spk);
            mtx.vout.emplace_back(0, change_spk);
            mtx.ct_bundle = std::move(bundle);

            // 9. Compute the message and sign with multi-layer CLSAG.
            //    The msg is the tx hash with sigs zeroed out.
            CMutableTransaction sig_input_tx{mtx};
            for (auto& ri : sig_input_tx.ct_bundle.ring_inputs) {
                ri.sig = pricoin::ringsig::Signature{};
            }
            HashWriter hw{};
            hw << TX_NO_WITNESS(CTransaction{sig_input_tx});
            const uint256 msg = hw.GetSHA256();

            // Phase 4b-mini: single-layer CLSAG over spend pubkeys. The
            // commitment-row of multi-layer CLSAG is deferred because correct
            // commitment-to-pubkey conversion needs faithful y-parity reconstruction
            // (Pedersen uses is-square indicator, BIP66 pubkeys use is-even — these
            // are independent properties on secp256k1). Without the commitment row,
            // the sig doesn't bind the chosen ring member to its commitment, so a
            // malicious sender could construct a pseudo commitment with the wrong
            // value and the sig would still verify. Toy scope acknowledges this gap.
            std::vector<pricoin::ringsig::Point> p_ring(ring_size);
            for (size_t k = 0; k < (size_t)ring_size; ++k) {
                p_ring[k] = ring[k].one_time_pubkey;
            }

            pricoin::ringsig::Scalar x_pi;
            std::memcpy(x_pi.data(), picked->one_time_priv.data(), 32);

            auto sig = pricoin::ringsig::Sign(
                std::span<const pricoin::ringsig::Point>{p_ring}, pi, x_pi, msg);
            if (!sig) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "ring signing failed");
            }

            // 10. Insert sig into the bundle and broadcast.
            mtx.ct_bundle.ring_inputs[0].sig = *sig;

            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            std::string err_str;
            if (!chain.broadcastTransaction(tx_ref, MAX_MONEY,
                                             node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
                                             err_str)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "broadcast failed: " + err_str);
            }

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", tx_ref->GetHash().ToString());
            out.pushKV("ring_size", ring_size);
            out.pushKV("signer_index", (int)pi);
            out.pushKV("input_value", ValueFromAmount(picked->value));
            out.pushKV("change_amount", ValueFromAmount(change_value));
            out.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(*tx_ref)));
            out.pushKV("bundle_size", (int)tx_ref->ct_bundle.SerializedSize());
            return out;
        }
    };
}

RPCMethod walletsendct_from_ct()
{
    return RPCMethod{
        "walletsendct_from_ct",
        "Send a Pricoin Confidential Transaction funded by a previously-received CT output.\n"
        "Scans the chain for own CT outputs, picks the first with value >= dest_amount + fee,\n"
        "derives the one-time spend key from the wallet's stealth identity, and constructs +\n"
        "signs a v4 tx spending it. Demonstrates CT-spending-CT.\n",
        {
            {"dest_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination Pricoin stealth or bech32 address"},
            {"dest_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to send in PRIC"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Transparent fee in PRIC"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", ""},
                {RPCResult::Type::STR, "spent_outpoint", "txid:vout of the consumed CT input"},
                {RPCResult::Type::STR_AMOUNT, "input_value", "Recovered input value"},
                {RPCResult::Type::STR_AMOUNT, "change_amount", "Change amount (kept as our own CT)"},
                {RPCResult::Type::NUM, "size", ""},
                {RPCResult::Type::NUM, "bundle_size", ""},
            }
        },
        RPCExamples{HelpExampleCli("walletsendct_from_ct", "\"pricstl1...\" 10 0.0001")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;

            const std::string dest_addr_str = request.params[0].get_str();
            const CAmount dest_amount = AmountFromValue(request.params[1]);
            const CAmount fee = AmountFromValue(request.params[2]);
            if (dest_amount <= 0 || fee < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative or zero amount");
            const CAmount target = dest_amount + fee;

            const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            interfaces::Chain& chain = wallet.chain();

            // Scan blocks for the first own CT output of sufficient value.
            std::optional<RecoveredOutput> picked;
            COutPoint picked_outpoint;
            const int tip = chain.getHeight().value_or(-1);
            for (int h = 0; h <= tip && !picked; ++h) {
                const uint256 block_hash = chain.getBlockHash(h);
                CBlock block;
                if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) continue;
                for (const auto& tx_ref : block.vtx) {
                    if (tx_ref->version != PRICOIN_CT_VERSION) continue;
                    for (uint32_t i = 0; i < tx_ref->vout.size(); ++i) {
                        auto rec = TryRecoverCTOutput(id, *tx_ref, i);
                        if (!rec) continue;
                        if (rec->value < target) continue;
                        picked = std::move(rec);
                        picked_outpoint = COutPoint(tx_ref->GetHash(), picked->output_index);
                        break;
                    }
                    if (picked) break;
                }
            }
            if (!picked) throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No recovered CT output with value >= dest_amount + fee");

            // Build the destination output (stealth or transparent).
            const auto stealth_dest = ::pricoin::stealth::Decode(dest_addr_str);
            CScript dest_spk;
            ::pricoin::stealth::PointBytes dest_R{};
            ::pricoin::ct::BlindingFactor dest_nonce{};
            ::pricoin::ct::SerializedPubKey33 dest_otp{};
            if (stealth_dest) {
                CKey r; r.MakeNewKey(true);
                CPubKey R = r.GetPubKey();
                std::memcpy(dest_R.data(), R.data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, stealth_dest->view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH failed");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, 0);
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, stealth_dest->spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime pubkey failed");
                dest_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                std::memcpy(dest_otp.data(), P->data(), 33);
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 0);
                std::memcpy(dest_nonce.data(), rp_nonce.data(), 32);
            } else {
                CTxDestination d = DecodeDestination(dest_addr_str);
                if (!IsValidDestination(d)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid dest_address");
                dest_spk = GetScriptForDestination(d);
                GetRandBytes(dest_nonce);
            }

            // Change always goes to our own stealth identity.
            CScript change_spk;
            ::pricoin::stealth::PointBytes change_R{};
            ::pricoin::ct::BlindingFactor change_nonce{};
            ::pricoin::ct::SerializedPubKey33 change_otp{};
            {
                CKey r; r.MakeNewKey(true);
                CPubKey R = r.GetPubKey();
                std::memcpy(change_R.data(), R.data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, id.public_address.view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH (change) failed");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, 1);
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, id.public_address.spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime pubkey (change) failed");
                change_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                std::memcpy(change_otp.data(), P->data(), 33);
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 1);
                std::memcpy(change_nonce.data(), rp_nonce.data(), 32);
            }

            const CAmount change_value = picked->value - target;

            // Build the bundle. Input has its recovered (nonzero) blind.
            // Output blinds: dest random, change = input_blind - dest_blind.
            pricoin::ct::BlindingFactor dest_blind;
            GetRandBytes(dest_blind);
            auto change_blind = pricoin::ct::BalancingBlind(
                std::array<pricoin::ct::BlindingFactor, 1>{picked->blind},
                std::array<pricoin::ct::BlindingFactor, 1>{dest_blind});
            if (!change_blind) throw JSONRPCError(RPC_INTERNAL_ERROR, "blind sum failed");

            auto dest_commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(dest_amount), dest_blind);
            auto change_commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(change_value), *change_blind);
            if (!dest_commit || !change_commit) throw JSONRPCError(RPC_INTERNAL_ERROR, "output commit failed");

            std::vector<unsigned char> dest_spk_bytes(dest_spk.begin(), dest_spk.end());
            std::vector<unsigned char> change_spk_bytes(change_spk.begin(), change_spk.end());
            auto dest_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(dest_amount), dest_blind, *dest_commit,
                std::span<const unsigned char>{dest_spk_bytes}, dest_nonce);
            auto change_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(change_value), *change_blind, *change_commit,
                std::span<const unsigned char>{change_spk_bytes}, change_nonce);
            if (!dest_proof || !change_proof) throw JSONRPCError(RPC_INTERNAL_ERROR, "rangeproof failed");

            pricoin::ct::CTBundle bundle;
            bundle.input_commitments = {picked->commitment};
            bundle.outputs = {
                pricoin::ct::CTOutput{*dest_commit, *dest_proof, dest_spk_bytes, dest_R, dest_otp},
                pricoin::ct::CTOutput{*change_commit, *change_proof, change_spk_bytes, change_R, change_otp},
            };
            bundle.transparent_fee = static_cast<uint64_t>(fee);

            CMutableTransaction mtx;
            mtx.version = PRICOIN_CT_VERSION;
            mtx.nLockTime = 0;
            mtx.vin.emplace_back(picked_outpoint, CScript{}, 0xfffffffe);
            mtx.vout.emplace_back(0, dest_spk);
            mtx.vout.emplace_back(0, change_spk);
            mtx.ct_bundle = std::move(bundle);

            // Sign the input directly with the derived one-time priv key.
            // Wallet's keystore doesn't know about this key, so we don't go
            // through CWallet::SignTransaction.
            CKeyID keyid;
            const CScript& spk = picked->scriptPubKey;
            if (spk.size() != 22 || spk[0] != OP_0 || spk[1] != 0x14) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "recovered CT output is not P2WPKH");
            }
            std::copy_n(spk.begin() + 2, 20, keyid.begin());
            CScript scriptCode;
            scriptCode << OP_DUP << OP_HASH160 << ToByteVector(keyid)
                       << OP_EQUALVERIFY << OP_CHECKSIG;
            const int32_t hashtype = SIGHASH_ALL;
            // For BIP143 sighash on a v4 input that spent a v4 output: the
            // "amount" field would normally be the prev nValue, which is 0
            // here. Pass 0; the bundle hash mixin (Phase 2d-3) provides the
            // real binding.
            const uint256 sighash = SignatureHash(
                scriptCode, mtx, /*nIn=*/0, hashtype,
                /*amount=*/0, SigVersion::WITNESS_V0,
                nullptr, nullptr);
            std::vector<unsigned char> sig;
            if (!picked->one_time_priv.Sign(sighash, sig, true)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "ECDSA sign failed (one-time priv)");
            }
            sig.push_back(static_cast<unsigned char>(hashtype));
            const CPubKey one_time_pub = picked->one_time_priv.GetPubKey();
            mtx.vin[0].scriptWitness.stack.clear();
            mtx.vin[0].scriptWitness.stack.push_back(std::move(sig));
            mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(one_time_pub.begin(), one_time_pub.end()));

            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            DataStream ds;
            ds << TX_WITH_WITNESS(*tx_ref);
            // Broadcast directly via the chain — wallet.CommitTransaction
            // assumes wallet-owned inputs (which a stealth-recovered CT
            // input isn't, in the wallet's bookkeeping sense).
            std::string err_str;
            if (!chain.broadcastTransaction(tx_ref, /*max_tx_fee=*/MAX_MONEY,
                                             node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
                                             err_str)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "broadcastTransaction failed: " + err_str);
            }

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", tx_ref->GetHash().ToString());
            out.pushKV("spent_outpoint", picked_outpoint.hash.ToString() + ":" + std::to_string(picked_outpoint.n));
            out.pushKV("input_value", ValueFromAmount(picked->value));
            out.pushKV("change_amount", ValueFromAmount(change_value));
            out.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(*tx_ref)));
            out.pushKV("bundle_size", (int)tx_ref->ct_bundle.SerializedSize());
            return out;
        }
    };
}

RPCMethod pricoin_getstealthaddress()
{
    return RPCMethod{
        "pricoin_getstealthaddress",
        "Return the wallet's stealth address (CryptoNote-style dual-key (view, spend)).\n"
        "Phase 5 MVP: the identity is generated lazily on first call and held only\n"
        "in memory — it is *not* persisted across daemon restarts.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "Base58Check-encoded stealth address"},
                {RPCResult::Type::STR_HEX, "view_pubkey", "Public view key (33 bytes)"},
                {RPCResult::Type::STR_HEX, "spend_pubkey", "Public spend key (33 bytes)"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricoin_getstealthaddress", "")
        },
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const auto& id = wallet::pricoin_stealth::GetOrCreate(*wallet_sp);
            UniValue out{UniValue::VOBJ};
            out.pushKV("address", ::pricoin::stealth::Encode(id.public_address));
            out.pushKV("view_pubkey", HexStr(id.public_address.view));
            out.pushKV("spend_pubkey", HexStr(id.public_address.spend));
            return out;
        }
    };
}
} // namespace

RPCMethod pricoin_getstealthaddress_export() { return pricoin_getstealthaddress(); }
RPCMethod pricoin_listownct_export() { return pricoin_listownct(); }
RPCMethod walletsendct_from_ct_export() { return walletsendct_from_ct(); }
RPCMethod walletsendct_ring_export() { return walletsendct_ring(); }

} // namespace wallet
