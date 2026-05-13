// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <node/context.h>
#include <pricoin/ct.h>
#include <pricoin/cttx.h>
#include <pricoin/adaptor_joint_ringsig.h>
#include <pricoin/adaptor_ringsig.h>
#include <pricoin/joint_ringsig.h>
#include <pricoin/ringsig.h>
#include <streams.h>
#include <primitives/transaction.h>
#include <random.h>
#include <rpc/register.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <streams.h>
#include <txmempool.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

// Build the scriptCode that BIP143 v0 requires for signing a P2WPKH input.
//   OP_DUP OP_HASH160 <20-byte pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
CScript P2WPKHScriptCode(const CKeyID& keyid)
{
    CScript code;
    code << OP_DUP << OP_HASH160 << ToByteVector(keyid)
         << OP_EQUALVERIFY << OP_CHECKSIG;
    return code;
}

RPCMethod pricoin_ct_send()
{
    return RPCMethod{
        "pricoin_ct_send",
        "Low-level CT builder. Builds, signs, and returns a hex-encoded Pricoin Confidential\n"
        "Transaction (tx version 4) spending one P2WPKH transparent input into two confidential\n"
        "outputs (destination + change). Two outputs are required because a single CT output\n"
        "cannot balance against a zero-blind transparent input — see Pedersen commitment math\n"
        "in src/pricoin/cttx.cpp. The returned hex can be submitted via sendrawtransaction.\n"
        "\n"
        "NOTE: This is a transparent-recipient builder. The destination address is a regular\n"
        "Pricoin bech32 (P2WPKH/P2WSH); the recipient can spend the output but CANNOT recover\n"
        "the hidden amount via stealth scan because no per-output tx_pubkey is published. For\n"
        "production payments to a stealth address (which let the recipient scan and recover\n"
        "values), use the wallet RPCs walletsendct / walletsendct_multi / walletsendct_ring.\n",
        {
            {"input_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Prev tx id of the input"},
            {"input_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Prev vout index"},
            {"input_wif", RPCArg::Type::STR, RPCArg::Optional::NO, "WIF private key for the input's P2WPKH"},
            {"dest_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Pricoin bech32 destination (any P2WPKH/P2WSH)"},
            {"dest_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Destination amount in PRIC"},
            {"change_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Pricoin bech32 address for change/balancing output"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Cleartext transparent fee in PRIC"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "Hex-encoded signed v4 transaction"},
                {RPCResult::Type::STR_HEX, "txid", "Transaction id (SHA-256d of the tx, no witness)"},
                {RPCResult::Type::NUM, "size", "Total serialized size in bytes (with witness, with bundle)"},
                {RPCResult::Type::NUM, "bundle_size", "Bundle size in bytes"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricoin_ct_send",
                "\"abc...\" 0 \"cTk...\" \"pricrt1q...\" 25.0 \"pricrt1q...\" 0.0001")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const std::string txid_hex = request.params[0].get_str();
            const int vout_idx = request.params[1].getInt<int>();
            const std::string wif = request.params[2].get_str();
            const std::string dest_addr = request.params[3].get_str();
            const CAmount dest_amount = AmountFromValue(request.params[4]);
            const std::string change_addr = request.params[5].get_str();
            const CAmount fee = AmountFromValue(request.params[6]);

            auto txid_opt = uint256::FromHex(txid_hex);
            if (!txid_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid input_txid");
            }
            const COutPoint prevout{Txid::FromUint256(*txid_opt), static_cast<uint32_t>(vout_idx)};

            // Look up prev coin to learn its value and scriptPubKey.
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            std::optional<Coin> coin_opt;
            {
                LOCK(cs_main);
                coin_opt = chainman.ActiveChainstate().CoinsTip().GetCoin(prevout);
            }
            if (!coin_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Input outpoint not in current UTXO set");
            }
            const Coin& coin = *coin_opt;
            if (coin.IsSpent()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Input is already spent");
            if (coin.out.nValue <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Phase 2d: only transparent prev outputs supported");
            }
            const CAmount input_value = coin.out.nValue;
            const CAmount change_value = input_value - dest_amount - fee;
            if (change_value < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "input_value < dest_amount + fee");
            }
            if (dest_amount < 0 || fee < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative amount or fee");
            }

            // Decode WIF and confirm pubkey hash matches the prev script.
            CKey key = DecodeSecret(wif);
            if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid WIF");
            const CPubKey pubkey = key.GetPubKey();
            const CKeyID keyid = pubkey.GetID();
            const CScript expected_p2wpkh = CScript() << OP_0 << ToByteVector(keyid);
            if (coin.out.scriptPubKey != expected_p2wpkh) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "WIF does not unlock this prev output (must be P2WPKH for the WIF's pubkey)");
            }

            auto script_for_addr = [](const std::string& a, const char* name) {
                CTxDestination d = DecodeDestination(a);
                if (!IsValidDestination(d)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid ") + name);
                }
                return GetScriptForDestination(d);
            };
            const CScript dest_spk = script_for_addr(dest_addr, "dest_address");
            const CScript change_spk = script_for_addr(change_addr, "change_address");

            // Build the CT bundle.
            // Inputs: one transparent prev output → Commit(input_value, blind=0).
            pricoin::ct::BlindingFactor zero_blind{};
            auto in_commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(input_value), zero_blind);
            if (!in_commit) throw JSONRPCError(RPC_INTERNAL_ERROR, "input commit failed");

            // Outputs: dest gets a random blind; change blind is derived to balance.
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

            pricoin::ct::BlindingFactor nonce_dest, nonce_change;
            GetRandBytes(nonce_dest);
            GetRandBytes(nonce_change);
            auto dest_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(dest_amount), dest_blind, *dest_commit,
                std::span<const unsigned char>{dest_spk_bytes}, nonce_dest);
            auto change_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(change_value), *change_blind, *change_commit,
                std::span<const unsigned char>{change_spk_bytes}, nonce_change);
            if (!dest_proof || !change_proof) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "rangeproof failed");
            }

            pricoin::ct::CTBundle bundle;
            bundle.input_commitments = {*in_commit};
            bundle.outputs = {
                pricoin::ct::CTOutput{*dest_commit, *dest_proof, dest_spk_bytes},
                pricoin::ct::CTOutput{*change_commit, *change_proof, change_spk_bytes},
            };
            bundle.transparent_fee = static_cast<uint64_t>(fee);

            // Build the mutable tx.
            CMutableTransaction mtx;
            mtx.version = PRICOIN_CT_VERSION;
            mtx.nLockTime = 0;
            mtx.vin.emplace_back(prevout, CScript{}, /*nSequence=*/0xfffffffe);
            mtx.vout.emplace_back(0, dest_spk);
            mtx.vout.emplace_back(0, change_spk);
            mtx.ct_bundle = std::move(bundle);

            // Sign the input. Only P2WPKH supported for now: scriptCode is the
            // implicit P2PKH for the same pubkey hash. The sighash includes the
            // bundle hash (added by the v4 path in script/interpreter.cpp).
            const CScript scriptCode = P2WPKHScriptCode(keyid);
            const int32_t hashtype = SIGHASH_ALL;
            const uint256 sighash = SignatureHash(
                scriptCode, mtx, /*nIn=*/0, hashtype,
                input_value, SigVersion::WITNESS_V0,
                /*cache=*/nullptr, /*sighash_cache=*/nullptr);

            std::vector<unsigned char> sig;
            if (!key.Sign(sighash, sig, /*grind=*/true)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "ECDSA signing failed");
            }
            sig.push_back(static_cast<unsigned char>(hashtype));

            // Witness: <signature> <pubkey>
            mtx.vin[0].scriptWitness.stack.clear();
            mtx.vin[0].scriptWitness.stack.push_back(std::move(sig));
            mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));

            // Serialize and report.
            CTransaction tx{std::move(mtx)};
            DataStream ds;
            ds << TX_WITH_WITNESS(tx);
            UniValue out{UniValue::VOBJ};
            out.pushKV("hex", HexStr(ds));
            out.pushKV("txid", tx.GetHash().ToString());
            out.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(tx)));
            out.pushKV("bundle_size", (int)tx.ct_bundle.SerializedSize());
            return out;
        }
    };
}

// ─────────────────────────────────────────────────────────────────
// Atomic-swap stage 2b — cooperative CLSAG signing RPCs.
// Round-by-round message-passing protocol for two (or more) parties
// holding additive shares of a single spend secret. See
// doc/atomic-swap-protocol.md for the full protocol description.
// ─────────────────────────────────────────────────────────────────

namespace js_helpers {

// Parse a 33-byte compressed pubkey from hex.
::pricoin::ringsig::Point ParsePoint33(const std::string& hex, const char* what)
{
    auto bytes = TryParseHex<unsigned char>(hex);
    if (!bytes || bytes->size() != 33) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            std::string(what) + " must be 33-byte compressed pubkey hex");
    }
    ::pricoin::ringsig::Point p;
    std::copy(bytes->begin(), bytes->end(), p.begin());
    return p;
}

// Parse a 32-byte scalar from hex.
::pricoin::ringsig::Scalar ParseScalar32(const std::string& hex, const char* what)
{
    auto bytes = TryParseHex<unsigned char>(hex);
    if (!bytes || bytes->size() != 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            std::string(what) + " must be 32-byte scalar hex");
    }
    ::pricoin::ringsig::Scalar s;
    std::copy(bytes->begin(), bytes->end(), s.begin());
    return s;
}

// Parse a UniValue array of pubkey-hex strings into a Point[]. Used
// for single-layer ring inputs.
std::vector<::pricoin::ringsig::Point> ParseRing(const UniValue& arr)
{
    if (!arr.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ring must be an array");
    }
    std::vector<::pricoin::ringsig::Point> out;
    out.reserve(arr.size());
    for (size_t i = 0; i < arr.size(); ++i) {
        out.push_back(ParsePoint33(arr[i].get_str(), "ring[i]"));
    }
    return out;
}

// Parse an array of {P, W} objects into a MultiLayerMember[]. Used
// for multi-layer ring inputs.
std::vector<::pricoin::ringsig::MultiLayerMember> ParseMLRing(const UniValue& arr)
{
    if (!arr.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ring must be an array");
    }
    std::vector<::pricoin::ringsig::MultiLayerMember> out;
    out.reserve(arr.size());
    for (size_t i = 0; i < arr.size(); ++i) {
        const UniValue& member = arr[i];
        if (!member.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "ring[i] must be {P, W} object for multi-layer");
        }
        ::pricoin::ringsig::MultiLayerMember m;
        m.P = ParsePoint33(member.find_value("P").get_str(), "ring[i].P");
        m.W = ParsePoint33(member.find_value("W").get_str(), "ring[i].W");
        out.push_back(m);
    }
    return out;
}

// Parse an array of 32-byte scalar hex strings.
std::vector<::pricoin::ringsig::Scalar> ParseScalarArray(const UniValue& arr,
                                                         const char* what)
{
    if (!arr.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            std::string(what) + " must be an array");
    }
    std::vector<::pricoin::ringsig::Scalar> out;
    out.reserve(arr.size());
    for (size_t i = 0; i < arr.size(); ++i) {
        out.push_back(ParseScalar32(arr[i].get_str(), what));
    }
    return out;
}

std::string PointHex(const ::pricoin::ringsig::Point& p)
{
    return HexStr(p);
}

std::string ScalarHex(const ::pricoin::ringsig::Scalar& s)
{
    return HexStr(s);
}

} // namespace js_helpers

RPCMethod pricoin_jointspend_round1()
{
    return RPCMethod{
        "pricoin_jointspend_round1",
        "Stage 2b round 1 — generate this party's cooperative-CLSAG nonce + image partials.\n"
        "Returns a per-party private nonce (alpha) plus the public partials and a hiding\n"
        "commitment that the other party will verify in round 2.\n"
        "\n"
        "WARNING: alpha is a SECRET — keep it on this party's side only. Disclosing it before\n"
        "round 3 lets a counterparty extract this party's spend share.\n"
        "\n"
        "If z_share is provided, the call is in multi-layer mode and D_share is also returned.\n",
        {
            {"joint_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "33-byte compressed pubkey at ring[pi] (the joint spend pub)"},
            {"x_share", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "This party's 32-byte spend-secret share (sum across parties = x_pi)"},
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Session-binding tag (any hex; both parties must agree out-of-band)"},
            {"z_share", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                "Multi-layer: this party's 32-byte commitment-offset secret share"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "alpha", "32-byte private nonce — keep secret until round 3"},
                {RPCResult::Type::STR_HEX, "L_share", "33-byte alpha · G"},
                {RPCResult::Type::STR_HEX, "R_share", "33-byte alpha · H_p(P_pi)"},
                {RPCResult::Type::STR_HEX, "KI_share", "33-byte x_share · H_p(P_pi)"},
                {RPCResult::Type::STR_HEX, "D_share", /*optional=*/true,
                    "33-byte z_share · H_p(P_pi) (multi-layer only)"},
                {RPCResult::Type::STR_HEX, "commitment", "32-byte hash binding L/R/KI/D shares to session_id"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_round1", "<P_pi> <x_share> <session_id>")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            const auto P_pi    = ParsePoint33(request.params[0].get_str(), "joint_pubkey");
            const auto x_share = ParseScalar32(request.params[1].get_str(), "x_share");
            auto session_hex = request.params[2].get_str();
            auto session_bytes = TryParseHex<unsigned char>(session_hex);
            if (!session_bytes) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be hex");
            }

            const bool multi_layer = !request.params[3].isNull();
            ::pricoin::ringsig::Scalar z_share{};
            if (multi_layer) {
                z_share = ParseScalar32(request.params[3].get_str(), "z_share");
            }

            auto noncepart = ::pricoin::joint_ringsig::NonceGen(P_pi);
            if (!noncepart) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "NonceGen failed");
            }
            auto KI_share_opt = ::pricoin::joint_ringsig::KeyImageShare(P_pi, x_share);
            if (!KI_share_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "x_share invalid");
            }
            ::pricoin::ringsig::Point D_share{};
            if (multi_layer) {
                auto imgs = ::pricoin::joint_ringsig::KICommitImageShare(P_pi, x_share, z_share);
                if (!imgs) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "x/z share invalid");
                }
                D_share = imgs->D_share;
                // KI_share is the same as KICommitImageShare's KI_share — sanity:
                if (imgs->KI_share != *KI_share_opt) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "KI share mismatch");
                }
            }

            auto commit = ::pricoin::joint_ringsig::NonceCommit(
                std::span<const unsigned char>{*session_bytes},
                noncepart->L_share, noncepart->R_share, *KI_share_opt);
            // For commitment binding we mix in D_share too if present.
            if (multi_layer) {
                CSHA256 h;
                static constexpr char kTag[] = "pricoin/joint_ringsig/commit-ml-v1";
                h.Write(reinterpret_cast<const unsigned char*>(kTag), sizeof(kTag) - 1);
                h.Write(session_bytes->data(), session_bytes->size());
                h.Write(noncepart->L_share.data(), noncepart->L_share.size());
                h.Write(noncepart->R_share.data(), noncepart->R_share.size());
                h.Write(KI_share_opt->data(), KI_share_opt->size());
                h.Write(D_share.data(), D_share.size());
                h.Finalize(commit.data());
            }

            UniValue out{UniValue::VOBJ};
            out.pushKV("alpha",      ScalarHex(noncepart->alpha));
            out.pushKV("L_share",    PointHex(noncepart->L_share));
            out.pushKV("R_share",    PointHex(noncepart->R_share));
            out.pushKV("KI_share",   PointHex(*KI_share_opt));
            if (multi_layer) {
                out.pushKV("D_share", PointHex(D_share));
            }
            out.pushKV("commitment", ScalarHex(commit));
            return out;
        }
    };
}

namespace {
// Helper: recompute the round-1 commitment for a party given their
// public partials. Used by combine to verify each commitment.
::pricoin::ringsig::Scalar RecomputeCommit(
    std::span<const unsigned char> session_id,
    const ::pricoin::ringsig::Point& L_share,
    const ::pricoin::ringsig::Point& R_share,
    const ::pricoin::ringsig::Point& KI_share,
    const ::pricoin::ringsig::Point* D_share)
{
    if (!D_share) {
        return ::pricoin::joint_ringsig::NonceCommit(
            session_id, L_share, R_share, KI_share);
    }
    ::pricoin::ringsig::Scalar out;
    CSHA256 h;
    static constexpr char kTag[] = "pricoin/joint_ringsig/commit-ml-v1";
    h.Write(reinterpret_cast<const unsigned char*>(kTag), sizeof(kTag) - 1);
    h.Write(session_id.data(), session_id.size());
    h.Write(L_share.data(), L_share.size());
    h.Write(R_share.data(), R_share.size());
    h.Write(KI_share.data(), KI_share.size());
    h.Write(D_share->data(), D_share->size());
    h.Finalize(out.data());
    return out;
}
}

RPCMethod pricoin_jointspend_combine()
{
    return RPCMethod{
        "pricoin_jointspend_combine",
        "Stage 2b round 2 — combine all parties' round-1 partials, verify each\n"
        "commitment, and walk the ring deterministically to obtain c_pi (the\n"
        "closing challenge for the signer's index) and c0 (the published challenge).\n"
        "\n"
        "All parties run this with identical inputs and obtain the same outputs.\n",
        {
            {"ring", RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Single-layer: array of 33-byte compressed pubkey hex strings.",
                {{"P", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"ring_ml", RPCArg::Type::ARR, RPCArg::Optional::OMITTED,
                "Multi-layer: array of {P, W} objects. If present, ring is ignored.",
                {{"member", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                  {{"P", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"W", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""}}}}},
            {"pi", RPCArg::Type::NUM, RPCArg::Optional::NO, "Signer's index"},
            {"msg", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte message hash"},
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Session-binding tag (must match round 1)"},
            {"parties", RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Array of party round-1 outputs (without alpha).",
                {{"party", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                  {{"L_share",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"R_share",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"KI_share",   RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"D_share",    RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                       "Required iff multi-layer"},
                   {"commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""}}}}},
            {"s_others", RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Per-index closing scalars for non-signer ring positions (entry at pi is ignored).",
                {{"s", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "KI", "Joint key image"},
                {RPCResult::Type::STR_HEX, "D",  /*optional=*/true,  "Joint commitment image (multi-layer only)"},
                {RPCResult::Type::STR_HEX, "L_pi", "Joint α · G"},
                {RPCResult::Type::STR_HEX, "R_pi", "Joint α · H_p(P_pi)"},
                {RPCResult::Type::STR_HEX, "mu_P", /*optional=*/true, "μ_P (multi-layer only)"},
                {RPCResult::Type::STR_HEX, "mu_C", /*optional=*/true, "μ_C (multi-layer only)"},
                {RPCResult::Type::STR_HEX, "c_pi", "Closing challenge at the signer's index"},
                {RPCResult::Type::STR_HEX, "c0",   "Initial challenge (goes into the published Signature)"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_combine", "<args>")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            const bool multi_layer = !request.params[1].isNull();

            const size_t pi = static_cast<size_t>(request.params[2].getInt<int>());
            const auto msg_scalar = ParseScalar32(request.params[3].get_str(), "msg");
            uint256 msg;
            std::copy(msg_scalar.begin(), msg_scalar.end(), msg.begin());

            const auto session_bytes = TryParseHex<unsigned char>(request.params[4].get_str());
            if (!session_bytes) throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be hex");

            const UniValue& parties = request.params[5];
            if (!parties.isArray() || parties.size() < 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "parties must be an array of >= 2 entries");
            }

            // Verify each party's commitment, collect shares.
            std::vector<::pricoin::ringsig::Point> ki_shares, d_shares, L_shares, R_shares;
            for (size_t i = 0; i < parties.size(); ++i) {
                const UniValue& p = parties[i];
                ::pricoin::ringsig::Point L  = ParsePoint33(p.find_value("L_share").get_str(), "L_share");
                ::pricoin::ringsig::Point R  = ParsePoint33(p.find_value("R_share").get_str(), "R_share");
                ::pricoin::ringsig::Point KI = ParsePoint33(p.find_value("KI_share").get_str(), "KI_share");
                ::pricoin::ringsig::Scalar claimed = ParseScalar32(
                    p.find_value("commitment").get_str(), "commitment");

                std::optional<::pricoin::ringsig::Point> D_opt;
                if (multi_layer) {
                    D_opt = ParsePoint33(p.find_value("D_share").get_str(), "D_share");
                    d_shares.push_back(*D_opt);
                }
                auto recomputed = RecomputeCommit(
                    std::span<const unsigned char>{*session_bytes},
                    L, R, KI, D_opt ? &*D_opt : nullptr);
                if (recomputed != claimed) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("party %u commitment mismatch", static_cast<unsigned>(i)));
                }
                ki_shares.push_back(KI);
                L_shares.push_back(L);
                R_shares.push_back(R);
            }

            auto KI_opt = ::pricoin::joint_ringsig::CombinePoints(
                std::span<const ::pricoin::ringsig::Point>{ki_shares});
            if (!KI_opt) throw JSONRPCError(RPC_INTERNAL_ERROR, "KI combine failed");
            auto L_pi_opt = ::pricoin::joint_ringsig::CombinePoints(
                std::span<const ::pricoin::ringsig::Point>{L_shares});
            if (!L_pi_opt) throw JSONRPCError(RPC_INTERNAL_ERROR, "L combine failed");
            auto R_pi_opt = ::pricoin::joint_ringsig::CombinePoints(
                std::span<const ::pricoin::ringsig::Point>{R_shares});
            if (!R_pi_opt) throw JSONRPCError(RPC_INTERNAL_ERROR, "R combine failed");

            const auto s_others = ParseScalarArray(request.params[6], "s_others");

            UniValue out{UniValue::VOBJ};
            out.pushKV("KI", PointHex(*KI_opt));
            out.pushKV("L_pi", PointHex(*L_pi_opt));
            out.pushKV("R_pi", PointHex(*R_pi_opt));

            if (!multi_layer) {
                auto ring = ParseRing(request.params[0]);
                if (s_others.size() != ring.size()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "s_others size != ring size");
                }
                auto walk = ::pricoin::joint_ringsig::WalkRing(
                    std::span<const ::pricoin::ringsig::Point>{ring}, pi, msg,
                    *KI_opt, *L_pi_opt, *R_pi_opt,
                    std::span<const ::pricoin::ringsig::Scalar>{s_others});
                if (!walk) throw JSONRPCError(RPC_INTERNAL_ERROR, "WalkRing failed");
                out.pushKV("c_pi", ScalarHex(walk->c_pi));
                out.pushKV("c0",   ScalarHex(walk->c0));
            } else {
                auto ring = ParseMLRing(request.params[1]);
                if (s_others.size() != ring.size()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "s_others size != ring size");
                }
                auto D_opt = ::pricoin::joint_ringsig::CombinePoints(
                    std::span<const ::pricoin::ringsig::Point>{d_shares});
                if (!D_opt) throw JSONRPCError(RPC_INTERNAL_ERROR, "D combine failed");

                auto mu = ::pricoin::joint_ringsig::ComputeMu(
                    std::span<const ::pricoin::ringsig::MultiLayerMember>{ring},
                    *KI_opt, *D_opt);
                if (!mu) throw JSONRPCError(RPC_INTERNAL_ERROR, "ComputeMu failed");

                auto walk = ::pricoin::joint_ringsig::WalkRingMultiLayer(
                    std::span<const ::pricoin::ringsig::MultiLayerMember>{ring}, pi, msg,
                    *KI_opt, *D_opt, *L_pi_opt, *R_pi_opt,
                    std::span<const ::pricoin::ringsig::Scalar>{s_others});
                if (!walk) throw JSONRPCError(RPC_INTERNAL_ERROR, "WalkRingMultiLayer failed");

                out.pushKV("D",    PointHex(*D_opt));
                out.pushKV("mu_P", ScalarHex(mu->mu_P));
                out.pushKV("mu_C", ScalarHex(mu->mu_C));
                out.pushKV("c_pi", ScalarHex(walk->c_pi));
                out.pushKV("c0",   ScalarHex(walk->c0));
            }
            return out;
        }
    };
}

RPCMethod pricoin_jointspend_share()
{
    return RPCMethod{
        "pricoin_jointspend_share",
        "Stage 2b round 3 — compute this party's closing share s_share = α − c_pi · x.\n"
        "For multi-layer mode (mu_P + mu_C provided), x = μ_P · x_share + μ_C · z_share.\n",
        {
            {"alpha",   RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte private nonce from round 1"},
            {"c_pi",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte closing challenge from combine"},
            {"x_share", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte spend-secret share"},
            {"z_share", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Multi-layer: 32-byte commitment-offset share"},
            {"mu_P",    RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Multi-layer: μ_P from combine"},
            {"mu_C",    RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Multi-layer: μ_C from combine"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "s_share", "32-byte close share"}}
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_share", "<args>")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            const auto alpha   = ParseScalar32(request.params[0].get_str(), "alpha");
            const auto c_pi    = ParseScalar32(request.params[1].get_str(), "c_pi");
            const auto x_share = ParseScalar32(request.params[2].get_str(), "x_share");

            const bool multi_layer = !request.params[3].isNull();
            std::optional<::pricoin::ringsig::Scalar> sshare;
            if (!multi_layer) {
                sshare = ::pricoin::joint_ringsig::CloseShare(alpha, c_pi, x_share);
            } else {
                if (request.params[4].isNull() || request.params[5].isNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "multi-layer mode requires mu_P and mu_C");
                }
                const auto z_share = ParseScalar32(request.params[3].get_str(), "z_share");
                ::pricoin::joint_ringsig::MultiLayerMu mu{
                    ParseScalar32(request.params[4].get_str(), "mu_P"),
                    ParseScalar32(request.params[5].get_str(), "mu_C"),
                };
                auto a = ::pricoin::joint_ringsig::AggregateShare(mu, x_share, z_share);
                if (!a) throw JSONRPCError(RPC_INVALID_PARAMETER, "aggregate share failed");
                sshare = ::pricoin::joint_ringsig::CloseShare(alpha, c_pi, *a);
            }
            if (!sshare) throw JSONRPCError(RPC_INTERNAL_ERROR, "CloseShare failed");
            UniValue out{UniValue::VOBJ};
            out.pushKV("s_share", ScalarHex(*sshare));
            return out;
        }
    };
}

RPCMethod pricoin_jointspend_assemble()
{
    return RPCMethod{
        "pricoin_jointspend_assemble",
        "Stage 2b — combine all parties' s_pi shares with the rest of the ring data\n"
        "into a fully-formed CLSAG signature, hex-encoded.\n",
        {
            {"KI",  RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Joint key image (33 bytes)"},
            {"c0",  RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Initial challenge (32 bytes)"},
            {"s_others", RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Per-index closing scalars (entries at indices != pi).",
                {{"s", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"s_pi_shares", RPCArg::Type::ARR, RPCArg::Optional::NO,
                "All parties' s-shares (32-byte hex each). Summed mod n to obtain s_pi.",
                {{"s", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"pi",  RPCArg::Type::NUM, RPCArg::Optional::NO, "Signer's index"},
            {"D",   RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                "Joint commitment image (multi-layer only). Omit for single-layer."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "signature_hex", "Serialised pricoin::ringsig::Signature"}}
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_assemble", "<args>")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            const auto KI = ParsePoint33(request.params[0].get_str(), "KI");
            const auto c0 = ParseScalar32(request.params[1].get_str(), "c0");
            auto s_vec    = ParseScalarArray(request.params[2], "s_others");
            const auto s_pi_shares = ParseScalarArray(request.params[3], "s_pi_shares");
            const size_t pi = static_cast<size_t>(request.params[4].getInt<int>());
            ::pricoin::ringsig::Point D{};  // zero == single-layer marker
            if (!request.params[5].isNull()) {
                D = ParsePoint33(request.params[5].get_str(), "D");
            }
            if (pi >= s_vec.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "pi out of range");
            }

            auto s_pi = ::pricoin::joint_ringsig::CombineScalars(
                std::span<const ::pricoin::ringsig::Scalar>{s_pi_shares});
            if (!s_pi) throw JSONRPCError(RPC_INTERNAL_ERROR, "s_pi combine failed");
            s_vec[pi] = *s_pi;

            ::pricoin::ringsig::Signature sig;
            sig.key_image = KI;
            sig.commitment_image = D;
            sig.c0 = c0;
            sig.s = std::move(s_vec);

            DataStream ds;
            ds << sig;
            UniValue out{UniValue::VOBJ};
            out.pushKV("signature_hex", HexStr(ds));
            return out;
        }
    };
}

RPCMethod pricoin_jointspend_verify()
{
    return RPCMethod{
        "pricoin_jointspend_verify",
        "Verify a (cooperative or single-party) CLSAG signature against a ring + msg.\n"
        "Inferring single vs multi-layer from the presence of the ring_ml argument.\n",
        {
            {"ring", RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Single-layer: array of pubkey hex strings.",
                {{"P", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"ring_ml", RPCArg::Type::ARR, RPCArg::Optional::OMITTED,
                "Multi-layer: array of {P, W} objects.",
                {{"member", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                  {{"P", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"W", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""}}}}},
            {"msg", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte message hash"},
            {"signature_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Hex-encoded pricoin::ringsig::Signature"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "valid", "True iff signature verifies"}}
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_verify", "<args>")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            const bool multi_layer = !request.params[1].isNull();
            const auto msg_scalar = ParseScalar32(request.params[2].get_str(), "msg");
            uint256 msg;
            std::copy(msg_scalar.begin(), msg_scalar.end(), msg.begin());

            auto sig_bytes = TryParseHex<unsigned char>(request.params[3].get_str());
            if (!sig_bytes) throw JSONRPCError(RPC_INVALID_PARAMETER, "signature_hex invalid");
            DataStream ds{std::span<const unsigned char>{*sig_bytes}};
            ::pricoin::ringsig::Signature sig;
            try {
                ds >> sig;
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    std::string("signature deserialise failed: ") + e.what());
            }

            bool valid = false;
            if (!multi_layer) {
                auto ring = ParseRing(request.params[0]);
                valid = ::pricoin::ringsig::Verify(
                    std::span<const ::pricoin::ringsig::Point>{ring}, sig, msg);
            } else {
                auto ring = ParseMLRing(request.params[1]);
                valid = ::pricoin::ringsig::VerifyMultiLayer(
                    std::span<const ::pricoin::ringsig::MultiLayerMember>{ring}, sig, msg);
            }
            UniValue out{UniValue::VOBJ};
            out.pushKV("valid", valid);
            return out;
        }
    };
}

RPCMethod pricoin_pubkey_from_scalar()
{
    return RPCMethod{
        "pricoin_pubkey_from_scalar",
        "Compute the 33-byte compressed pubkey for a 32-byte scalar (= scalar · G).\n"
        "Helper for recovering an in-flight coopsign session when the dialog's\n"
        "auto-derive missed a Z_pub field: paste the corresponding z_self or\n"
        "z_other into this RPC, paste the returned pubkey into the dialog.\n",
        {
            {"scalar", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte secret hex"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "pubkey", "33-byte compressed pubkey hex"}}
        },
        RPCExamples{HelpExampleCli("pricoin_pubkey_from_scalar", "<32-byte hex>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const std::string hex = request.params[0].get_str();
            auto bytes = TryParseHex<unsigned char>(hex);
            if (!bytes || bytes->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "scalar must be 32-byte hex");
            }
            CKey k;
            k.Set(bytes->begin(), bytes->end(), /*compressed=*/true);
            if (!k.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "scalar is not a valid secp256k1 secret key");
            }
            const CPubKey p = k.GetPubKey();
            UniValue out{UniValue::VOBJ};
            out.pushKV("pubkey", HexStr(std::span<const unsigned char>{p.begin(), p.size()}));
            return out;
        }
    };
}

// ─────────────────────────────────────────────────────────────────
// Atomic-swap phase 5 — cooperative adaptor-CLSAG wire RPCs.
//
// Mirror of the non-adaptor cooperative RPCs above, but for the
// adaptor variant per doc/adaptor-clsag.md §4 (single-layer). The
// adaptor flow embeds a cross-chain secret t (encoded as 33-byte
// T_G + matching T_H + DLEQ proof binding them). Output is an
// `AdaptorPreSignature` blob; once the holder of `t` calls Adapt
// and broadcasts, anyone with the pre-sig can Extract t from the
// on-chain CLSAG signature.
//
// Round-3 close-share computation is identical math to the
// non-adaptor case (`s_share = α − c_pi · x` mod n) — callers
// reuse the existing `pricoin_jointspend_share` for that step.
//
// FLOW:
//   0.  pricoin_adaptor_compute_points(t, P_pi)        → {T_G, T_H}
//       pricoin_adaptor_dleq_prove(t, P_pi, T_G, T_H, label, payload)
//                                                       → dleq_t (hex)
//       pricoin_adaptor_dleq_verify(...)               → {valid: bool}
//   1.  pricoin_jointspend_adaptor_round1   (× each party)
//                                            → AdaptorNonceShare-shaped JSON
//   2.  pricoin_jointspend_adaptor_combine  (anyone)
//                                            → c_pi + walk + shifted-anchor data
//   3.  pricoin_jointspend_share            (× each party — reused)
//   4.  pricoin_jointspend_adaptor_assemble (anyone)
//                                            → AdaptorPreSignature blob
//   5.  pricoin_jointspend_adaptor_verify_presig (off-chain)
//   6.  pricoin_jointspend_adaptor_adapt    (the t holder)
//                                            → standard CLSAG Signature blob
//   7.  pricoin_jointspend_adaptor_extract  (the other party)
//                                            → recovered t (32 bytes)
// ─────────────────────────────────────────────────────────────────

namespace par  = ::pricoin::adaptor_ringsig;
namespace pajr = ::pricoin::adaptor_joint_ringsig;

namespace adaptor_helpers {

template <typename T>
std::vector<unsigned char> SerializeBlob(const T& obj)
{
    DataStream ds;
    ds << obj;
    return std::vector<unsigned char>(UCharCast(ds.data()),
                                       UCharCast(ds.data()) + ds.size());
}

template <typename T>
std::optional<T> ParseBlob(const std::string& hex)
{
    auto bytes = TryParseHex<unsigned char>(hex);
    if (!bytes) return std::nullopt;
    DataStream ds{std::span<const unsigned char>{*bytes}};
    T obj;
    try {
        ds >> obj;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    return obj;
}

std::span<const unsigned char> ToBytesSpan(const std::vector<unsigned char>& v)
{
    return std::span<const unsigned char>{v};
}

std::vector<unsigned char> ParseSessionLabel(const UniValue& v, const char* what)
{
    auto bytes = TryParseHex<unsigned char>(v.get_str());
    if (!bytes) {
        // Allow plaintext label too — convenient for tests.
        const auto& s = v.get_str();
        return std::vector<unsigned char>(s.begin(), s.end());
    }
    return *bytes;
}

} // namespace adaptor_helpers

RPCMethod pricoin_adaptor_compute_points()
{
    return RPCMethod{
        "pricoin_adaptor_compute_points",
        "Compute the adaptor points T_G = t·G and T_H = t·H_p(P_pi) for a\n"
        "scalar t and a ring-position pubkey P_pi. Both points use the same\n"
        "t — the cross-chain binding (a foreign-chain leg uses T_G alone, the\n"
        "PRIC leg uses both via the DLEQ proof).\n",
        {
            {"t",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte adaptor secret"},
            {"P_pi", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte joint pubkey at signer index"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "T_G", "33-byte t·G"},
                {RPCResult::Type::STR_HEX, "T_H", "33-byte t·H_p(P_pi)"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_adaptor_compute_points", "<t> <P_pi>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            auto t    = ParseScalar32(request.params[0].get_str(), "t");
            auto P_pi = ParsePoint33(request.params[1].get_str(), "P_pi");
            auto adaptor = par::ComputeAdaptorPoints(t, P_pi);
            if (!adaptor) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "ComputeAdaptorPoints failed (invalid t or P_pi)");
            UniValue out{UniValue::VOBJ};
            out.pushKV("T_G", PointHex(adaptor->T_G));
            out.pushKV("T_H", PointHex(adaptor->T_H));
            return out;
        }
    };
}

RPCMethod pricoin_adaptor_dleq_prove()
{
    return RPCMethod{
        "pricoin_adaptor_dleq_prove",
        "Construct a Chaum-Pedersen DLEQ proof binding (T_G, T_H) to the\n"
        "same scalar t over generators (G, H_p(P_pi)). Both parties exchange\n"
        "this in setup so the receiver can confirm the adaptor materials are\n"
        "well-formed before committing nonces.\n",
        {
            {"t",                RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte adaptor secret"},
            {"P_pi",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte joint pubkey"},
            {"T_G",              RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte t·G"},
            {"T_H",              RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte t·H_p(P_pi)"},
            {"session_label",    RPCArg::Type::STR,     RPCArg::Optional::NO, "Domain tag (hex or raw string)"},
            {"session_payload",  RPCArg::Type::STR,     RPCArg::Optional::NO, "Session bytes (hex or raw string)"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "dleq", "Serialized DLEQProof bytes"}}
        },
        RPCExamples{HelpExampleCli("pricoin_adaptor_dleq_prove", "<t> <P_pi> <T_G> <T_H> <label> <payload>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            using namespace adaptor_helpers;
            auto t    = ParseScalar32(request.params[0].get_str(), "t");
            auto P_pi = ParsePoint33(request.params[1].get_str(), "P_pi");
            par::AdaptorPoints adaptor;
            adaptor.T_G = ParsePoint33(request.params[2].get_str(), "T_G");
            adaptor.T_H = ParsePoint33(request.params[3].get_str(), "T_H");
            auto label   = ParseSessionLabel(request.params[4], "session_label");
            auto payload = ParseSessionLabel(request.params[5], "session_payload");
            auto proof = par::MakeDLEQProof(t, P_pi, adaptor, ToBytesSpan(label), ToBytesSpan(payload));
            if (!proof) throw JSONRPCError(RPC_INVALID_PARAMETER, "MakeDLEQProof failed");
            UniValue out{UniValue::VOBJ};
            out.pushKV("dleq", HexStr(SerializeBlob(*proof)));
            return out;
        }
    };
}

RPCMethod pricoin_adaptor_dleq_verify()
{
    return RPCMethod{
        "pricoin_adaptor_dleq_verify",
        "Verify a DLEQ proof for (T_G, T_H, t).\n",
        {
            {"P_pi",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"T_G",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"T_H",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"dleq",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Serialized DLEQProof"},
            {"session_label",   RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
            {"session_payload", RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "valid", "true iff the DLEQ verifies"}}
        },
        RPCExamples{HelpExampleCli("pricoin_adaptor_dleq_verify", "<P_pi> <T_G> <T_H> <dleq> <label> <payload>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            using namespace adaptor_helpers;
            auto P_pi = ParsePoint33(request.params[0].get_str(), "P_pi");
            par::AdaptorPoints adaptor;
            adaptor.T_G = ParsePoint33(request.params[1].get_str(), "T_G");
            adaptor.T_H = ParsePoint33(request.params[2].get_str(), "T_H");
            auto dleq = ParseBlob<par::DLEQProof>(request.params[3].get_str());
            if (!dleq) throw JSONRPCError(RPC_INVALID_PARAMETER, "dleq must be valid serialized DLEQProof hex");
            auto label   = ParseSessionLabel(request.params[4], "session_label");
            auto payload = ParseSessionLabel(request.params[5], "session_payload");
            const bool ok = par::VerifyDLEQProof(P_pi, adaptor, *dleq, ToBytesSpan(label), ToBytesSpan(payload));
            UniValue out{UniValue::VOBJ};
            out.pushKV("valid", ok);
            return out;
        }
    };
}

RPCMethod pricoin_jointspend_adaptor_round1()
{
    return RPCMethod{
        "pricoin_jointspend_adaptor_round1",
        "Adaptor-CLSAG round 1 — generate this party's adaptor nonce share\n"
        "(α_X, L_share, R_share, KI_share) plus DLEQ-1 (binding α_X across\n"
        "G and H_p(P_pi)) and DLEQ-2 (binding x_X across G and H_p(P_pi)),\n"
        "plus the round-1 commitment.\n"
        "\n"
        "WARNING: alpha is SECRET — keep it on this party's side. Disclosing\n"
        "it before round 3 lets a counterparty extract this party's spend\n"
        "share via x_X = (α_X − ŝ_share_X) / c_pi.\n",
        {
            {"P_pi",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte joint pubkey at ring[pi]"},
            {"X_pub_X",         RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte public spend share = x_X · G"},
            {"x_X",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte spend-secret share"},
            {"T_G",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"T_H",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"session_label",   RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
            {"session_payload", RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "alpha",       "32-byte private nonce — keep secret until round 3"},
                {RPCResult::Type::STR_HEX, "L_share",     "33-byte α_X · G"},
                {RPCResult::Type::STR_HEX, "R_share",     "33-byte α_X · H_p(P_pi)"},
                {RPCResult::Type::STR_HEX, "KI_share",    "33-byte x_X · H_p(P_pi)"},
                {RPCResult::Type::STR_HEX, "dleq_alpha",  "Serialized DLEQProof bytes (DLEQ-1)"},
                {RPCResult::Type::STR_HEX, "dleq_x",      "Serialized DLEQProof bytes (DLEQ-2)"},
                {RPCResult::Type::STR_HEX, "commitment",  "32-byte hiding hash bound to session"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_adaptor_round1", "<P_pi> <X_pub_X> <x_X> <T_G> <T_H> <label> <payload>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            using namespace adaptor_helpers;
            auto P_pi    = ParsePoint33(request.params[0].get_str(), "P_pi");
            auto X_pub_X = ParsePoint33(request.params[1].get_str(), "X_pub_X");
            auto x_X     = ParseScalar32(request.params[2].get_str(), "x_X");
            par::AdaptorPoints adaptor;
            adaptor.T_G = ParsePoint33(request.params[3].get_str(), "T_G");
            adaptor.T_H = ParsePoint33(request.params[4].get_str(), "T_H");
            auto label   = ParseSessionLabel(request.params[5], "session_label");
            auto payload = ParseSessionLabel(request.params[6], "session_payload");

            auto share = pajr::NonceGenAdaptor(P_pi, X_pub_X, x_X, adaptor,
                ToBytesSpan(label), ToBytesSpan(payload));
            if (!share) throw JSONRPCError(RPC_INVALID_PARAMETER, "NonceGenAdaptor failed");

            UniValue out{UniValue::VOBJ};
            out.pushKV("alpha",       ScalarHex(share->alpha));
            out.pushKV("L_share",     PointHex(share->L_share));
            out.pushKV("R_share",     PointHex(share->R_share));
            out.pushKV("KI_share",    PointHex(share->KI_share));
            out.pushKV("dleq_alpha",  HexStr(SerializeBlob(share->dleq_alpha)));
            out.pushKV("dleq_x",      HexStr(SerializeBlob(share->dleq_x)));
            out.pushKV("commitment",  ScalarHex(share->commitment));
            return out;
        }
    };
}

RPCMethod pricoin_jointspend_adaptor_combine()
{
    return RPCMethod{
        "pricoin_jointspend_adaptor_combine",
        "Adaptor-CLSAG round 2 — verify each party's round-1 share (commitment\n"
        "+ DLEQ-1 + DLEQ-2), aggregate, apply the adaptor shift to L_pi/R_pi,\n"
        "and walk the ring deterministically. All parties run with identical\n"
        "inputs and obtain identical outputs.\n",
        {
            {"ring", RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Array of 33-byte compressed pubkey hex strings (single-layer).",
                {{"P", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"pi",              RPCArg::Type::NUM,     RPCArg::Optional::NO, "Signer's index"},
            {"msg",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte message hash"},
            {"T_G",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"T_H",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"dleq_t",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Serialized DLEQProof bytes (binds T_G, T_H, t)"},
            {"X_pub_shares",    RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Array of public spend shares (33-byte hex)",
                {{"X_pub", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"shares", RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Array of party round-1 outputs (without alpha)",
                {{"share", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                  {{"L_share",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"R_share",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"KI_share",   RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"dleq_alpha", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"dleq_x",     RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""}}}}},
            {"session_label",   RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
            {"session_payload", RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "KI",      "Joint key image (Σ KI_share)"},
                {RPCResult::Type::STR_HEX, "L_pi",    "Σ L_share"},
                {RPCResult::Type::STR_HEX, "R_pi",    "Σ R_share"},
                {RPCResult::Type::STR_HEX, "L_prime", "L_pi + T_G  (shifted anchor)"},
                {RPCResult::Type::STR_HEX, "R_prime", "R_pi + T_H  (shifted anchor)"},
                {RPCResult::Type::STR_HEX, "c_pi",    "Closing challenge at the signer's index"},
                {RPCResult::Type::STR_HEX, "c0",      "Initial challenge"},
                {RPCResult::Type::ARR,     "s_others",
                    "Per-index closing scalars for non-signer ring positions (entry at pi is filled by assemble)",
                    {{RPCResult::Type::STR_HEX, "s", "32-byte"}}},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_adaptor_combine", "<args>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            using namespace adaptor_helpers;
            auto ring = ParseRing(request.params[0]);
            const size_t pi = static_cast<size_t>(request.params[1].getInt<int>());
            const auto msg_scalar = ParseScalar32(request.params[2].get_str(), "msg");
            uint256 msg;
            std::copy(msg_scalar.begin(), msg_scalar.end(), msg.begin());

            par::AdaptorPoints adaptor;
            adaptor.T_G = ParsePoint33(request.params[3].get_str(), "T_G");
            adaptor.T_H = ParsePoint33(request.params[4].get_str(), "T_H");
            auto dleq_t = ParseBlob<par::DLEQProof>(request.params[5].get_str());
            if (!dleq_t) throw JSONRPCError(RPC_INVALID_PARAMETER, "dleq_t must be serialized DLEQProof hex");

            const UniValue& xs_arr = request.params[6];
            if (!xs_arr.isArray() || xs_arr.size() < 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "X_pub_shares must be array of >=2 entries");
            }
            std::vector<::pricoin::ringsig::Point> X_pub_shares;
            X_pub_shares.reserve(xs_arr.size());
            for (size_t i = 0; i < xs_arr.size(); ++i) {
                X_pub_shares.push_back(ParsePoint33(xs_arr[i].get_str(), "X_pub_share"));
            }

            const UniValue& shares_arr = request.params[7];
            if (!shares_arr.isArray() || shares_arr.size() != xs_arr.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "shares.size() must match X_pub_shares.size()");
            }
            std::vector<pajr::AdaptorNonceShare> shares;
            shares.reserve(shares_arr.size());
            for (size_t i = 0; i < shares_arr.size(); ++i) {
                const UniValue& s = shares_arr[i];
                pajr::AdaptorNonceShare ns;
                // alpha is intentionally not in the input — verifier doesn't have it.
                std::memset(ns.alpha.data(), 0, ns.alpha.size());
                ns.L_share  = ParsePoint33(s.find_value("L_share").get_str(),  "L_share");
                ns.R_share  = ParsePoint33(s.find_value("R_share").get_str(),  "R_share");
                ns.KI_share = ParsePoint33(s.find_value("KI_share").get_str(), "KI_share");
                auto da = ParseBlob<par::DLEQProof>(s.find_value("dleq_alpha").get_str());
                auto dx = ParseBlob<par::DLEQProof>(s.find_value("dleq_x").get_str());
                if (!da || !dx) throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("party %u dleq_alpha/dleq_x must be serialized DLEQProof hex", static_cast<unsigned>(i)));
                ns.dleq_alpha = *da;
                ns.dleq_x     = *dx;
                ns.commitment = ParseScalar32(s.find_value("commitment").get_str(), "commitment");
                shares.push_back(ns);
            }

            auto label   = ParseSessionLabel(request.params[8], "session_label");
            auto payload = ParseSessionLabel(request.params[9], "session_payload");

            auto out_combined = pajr::CombineAndWalk(
                std::span<const ::pricoin::ringsig::Point>{ring}, pi, msg,
                adaptor, *dleq_t,
                std::span<const ::pricoin::ringsig::Point>{X_pub_shares},
                std::span<const pajr::AdaptorNonceShare>{shares},
                ToBytesSpan(label), ToBytesSpan(payload));
            if (!out_combined) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "CombineAndWalk failed (DLEQ verify, commitment mismatch, or ring walk error)");

            UniValue out{UniValue::VOBJ};
            out.pushKV("KI",      PointHex(out_combined->KI));
            out.pushKV("L_pi",    PointHex(out_combined->L_pi));
            out.pushKV("R_pi",    PointHex(out_combined->R_pi));
            out.pushKV("L_prime", PointHex(out_combined->L_prime));
            out.pushKV("R_prime", PointHex(out_combined->R_prime));
            out.pushKV("c_pi",    ScalarHex(out_combined->c_pi));
            out.pushKV("c0",      ScalarHex(out_combined->c0));
            UniValue arr_so{UniValue::VARR};
            for (const auto& s : out_combined->s_others) arr_so.push_back(ScalarHex(s));
            out.pushKV("s_others", arr_so);
            return out;
        }
    };
}

RPCMethod pricoin_jointspend_adaptor_assemble()
{
    return RPCMethod{
        "pricoin_jointspend_adaptor_assemble",
        "Assemble round-3 close shares + the round-2 combined output into an\n"
        "AdaptorPreSignature blob. Caller passes back the round-2 output\n"
        "fields (KI, c0, c_pi, s_others) plus the round-3 close shares from\n"
        "each party (computed via pricoin_jointspend_share — the math is the\n"
        "same as the non-adaptor case).\n",
        {
            {"KI",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "From adaptor_combine"},
            {"L_pi",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"R_pi",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"L_prime",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"R_prime",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"c_pi",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"c0",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"s_others",      RPCArg::Type::ARR,     RPCArg::Optional::NO,
                "Per-index closing scalars from adaptor_combine.",
                {{"s", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"close_shares",  RPCArg::Type::ARR,     RPCArg::Optional::NO,
                "Per-party round-3 close shares (32-byte hex each).",
                {{"s", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"pi",            RPCArg::Type::NUM,     RPCArg::Optional::NO, "Signer's index"},
            {"T_G",           RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"T_H",           RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"dleq_t",        RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "presig", "Serialized AdaptorPreSignature bytes"}}
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_adaptor_assemble", "<args>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            using namespace adaptor_helpers;

            pajr::AdaptorCombineOutput combined;
            combined.KI      = ParsePoint33(request.params[0].get_str(), "KI");
            combined.L_pi    = ParsePoint33(request.params[1].get_str(), "L_pi");
            combined.R_pi    = ParsePoint33(request.params[2].get_str(), "R_pi");
            combined.L_prime = ParsePoint33(request.params[3].get_str(), "L_prime");
            combined.R_prime = ParsePoint33(request.params[4].get_str(), "R_prime");
            combined.c_pi    = ParseScalar32(request.params[5].get_str(), "c_pi");
            combined.c0      = ParseScalar32(request.params[6].get_str(), "c0");
            combined.s_others = ParseScalarArray(request.params[7], "s_others");

            const auto close_shares = ParseScalarArray(request.params[8], "close_shares");
            const size_t pi = static_cast<size_t>(request.params[9].getInt<int>());

            par::AdaptorPoints adaptor;
            adaptor.T_G = ParsePoint33(request.params[10].get_str(), "T_G");
            adaptor.T_H = ParsePoint33(request.params[11].get_str(), "T_H");
            auto dleq_t = ParseBlob<par::DLEQProof>(request.params[12].get_str());
            if (!dleq_t) throw JSONRPCError(RPC_INVALID_PARAMETER, "dleq_t must be serialized DLEQProof hex");

            auto presig = pajr::AssembleAdaptorPreSig(combined,
                std::span<const ::pricoin::ringsig::Scalar>{close_shares},
                pi, adaptor, *dleq_t);
            if (!presig) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "AssembleAdaptorPreSig failed (close shares didn't sum to a valid s_pi, etc.)");

            UniValue out{UniValue::VOBJ};
            out.pushKV("presig", HexStr(SerializeBlob(*presig)));
            return out;
        }
    };
}

// ─── Multi-layer adaptor variants ────────────────────────────────
//
// Single-layer adaptor produces a Signature with commitment_image
// left zeroed. Chain consensus uses VerifyMultiLayer which requires
// a valid commitment_image — so the single-layer flow can't actually
// land an adaptor-claim tx on chain. The ML variants below produce
// Signatures with commitment_image = joint D point, which validates
// under VerifyMultiLayer. Mirrors the single-layer RPCs above with
// added Z_pub_X (z_X·G) + Z_pub_shares + D_share + dleq_z handling.

RPCMethod pricoin_jointspend_adaptor_round1_ml()
{
    return RPCMethod{
        "pricoin_jointspend_adaptor_round1_ml",
        "Multi-layer adaptor-CLSAG round 1 — like adaptor_round1, plus a\n"
        "z_X spend-commitment-offset share (z_X·G = Z_pub_X) so the resulting\n"
        "sig validates under pricoin::ringsig::VerifyMultiLayer at consensus.\n",
        {
            {"P_pi",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte joint pubkey at ring[pi]"},
            {"X_pub_X",         RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte public spend share = x_X · G"},
            {"Z_pub_X",         RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte public commitment-offset share = z_X · G"},
            {"x_X",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte spend-secret share"},
            {"z_X",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte commitment-offset secret share"},
            {"T_G",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"T_H",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"session_label",   RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
            {"session_payload", RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "alpha",       ""},
                {RPCResult::Type::STR_HEX, "L_share",     ""},
                {RPCResult::Type::STR_HEX, "R_share",     ""},
                {RPCResult::Type::STR_HEX, "KI_share",    ""},
                {RPCResult::Type::STR_HEX, "D_share",     "33-byte z_X · H_p(P_pi) — new vs single-layer"},
                {RPCResult::Type::STR_HEX, "dleq_alpha",  ""},
                {RPCResult::Type::STR_HEX, "dleq_x",      ""},
                {RPCResult::Type::STR_HEX, "dleq_z",      "Serialized DLEQProof binding z_X across G and H_p(P_pi)"},
                {RPCResult::Type::STR_HEX, "commitment",  ""},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_adaptor_round1_ml",
            "<P_pi> <X_pub_X> <Z_pub_X> <x_X> <z_X> <T_G> <T_H> <label> <payload>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            using namespace adaptor_helpers;
            auto P_pi    = ParsePoint33(request.params[0].get_str(), "P_pi");
            auto X_pub_X = ParsePoint33(request.params[1].get_str(), "X_pub_X");
            auto Z_pub_X = ParsePoint33(request.params[2].get_str(), "Z_pub_X");
            auto x_X     = ParseScalar32(request.params[3].get_str(), "x_X");
            auto z_X     = ParseScalar32(request.params[4].get_str(), "z_X");
            par::AdaptorPoints adaptor;
            adaptor.T_G = ParsePoint33(request.params[5].get_str(), "T_G");
            adaptor.T_H = ParsePoint33(request.params[6].get_str(), "T_H");
            auto label   = ParseSessionLabel(request.params[7], "session_label");
            auto payload = ParseSessionLabel(request.params[8], "session_payload");

            auto share = pajr::NonceGenAdaptorML(P_pi, X_pub_X, Z_pub_X,
                x_X, z_X, adaptor,
                ToBytesSpan(label), ToBytesSpan(payload));
            if (!share) throw JSONRPCError(RPC_INVALID_PARAMETER, "NonceGenAdaptorML failed");

            UniValue out{UniValue::VOBJ};
            out.pushKV("alpha",       ScalarHex(share->alpha));
            out.pushKV("L_share",     PointHex(share->L_share));
            out.pushKV("R_share",     PointHex(share->R_share));
            out.pushKV("KI_share",    PointHex(share->KI_share));
            out.pushKV("D_share",     PointHex(share->D_share));
            out.pushKV("dleq_alpha",  HexStr(SerializeBlob(share->dleq_alpha)));
            out.pushKV("dleq_x",      HexStr(SerializeBlob(share->dleq_x)));
            out.pushKV("dleq_z",      HexStr(SerializeBlob(share->dleq_z)));
            out.pushKV("commitment",  ScalarHex(share->commitment));
            return out;
        }
    };
}

RPCMethod pricoin_jointspend_adaptor_combine_ml()
{
    return RPCMethod{
        "pricoin_jointspend_adaptor_combine_ml",
        "Multi-layer adaptor-CLSAG round 2 — like adaptor_combine, plus a\n"
        "second layer over W (commitment delta) so the resulting sig\n"
        "passes VerifyMultiLayer at consensus.\n",
        {
            {"ring_ml", RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Array of {P, W} objects (multi-layer ring members).",
                {{"member", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                  {{"P", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"W", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""}}}}},
            {"pi",              RPCArg::Type::NUM,     RPCArg::Optional::NO, ""},
            {"msg",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte msg"},
            {"T_G",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"T_H",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"dleq_t",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"X_pub_shares",    RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Per-party X_pub (33-byte hex)",
                {{"X_pub", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"Z_pub_shares",    RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Per-party Z_pub (33-byte hex)",
                {{"Z_pub", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"shares", RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Per-party multi-layer round-1 outputs (without alpha)",
                {{"share", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                  {{"L_share",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"R_share",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"KI_share",   RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"D_share",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"dleq_alpha", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"dleq_x",     RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"dleq_z",     RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""}}}}},
            {"session_label",   RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
            {"session_payload", RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "KI",      ""},
                {RPCResult::Type::STR_HEX, "D",       "Joint commitment image (Σ D_share) — new vs single-layer"},
                {RPCResult::Type::STR_HEX, "L_pi",    ""},
                {RPCResult::Type::STR_HEX, "R_pi",    ""},
                {RPCResult::Type::STR_HEX, "L_prime", ""},
                {RPCResult::Type::STR_HEX, "R_prime", ""},
                {RPCResult::Type::STR_HEX, "mu_P",    "MultiLayer μ_P scalar — new vs single-layer"},
                {RPCResult::Type::STR_HEX, "mu_C",    "MultiLayer μ_C scalar — new vs single-layer"},
                {RPCResult::Type::STR_HEX, "c_pi",    ""},
                {RPCResult::Type::STR_HEX, "c0",      ""},
                {RPCResult::Type::ARR,     "s_others", "",
                    {{RPCResult::Type::STR_HEX, "s", ""}}},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_adaptor_combine_ml", "<args>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            using namespace adaptor_helpers;

            // Parse ring_ml: array of {P, W} objects.
            const UniValue& ring_arr = request.params[0];
            if (!ring_arr.isArray() || ring_arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "ring_ml must be non-empty array of {P,W} objects");
            }
            std::vector<::pricoin::ringsig::MultiLayerMember> ring;
            ring.reserve(ring_arr.size());
            for (size_t i = 0; i < ring_arr.size(); ++i) {
                const UniValue& entry = ring_arr[i];
                if (!entry.isObject() || !entry.exists("P") || !entry.exists("W")) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "ring_ml entry must be {P, W} object");
                }
                ::pricoin::ringsig::MultiLayerMember m;
                m.P = ParsePoint33(entry["P"].get_str(), "ring_ml[i].P");
                m.W = ParsePoint33(entry["W"].get_str(), "ring_ml[i].W");
                ring.push_back(m);
            }

            const size_t pi = static_cast<size_t>(request.params[1].getInt<int>());
            const auto msg_scalar = ParseScalar32(request.params[2].get_str(), "msg");
            uint256 msg;
            std::copy(msg_scalar.begin(), msg_scalar.end(), msg.begin());

            par::AdaptorPoints adaptor;
            adaptor.T_G = ParsePoint33(request.params[3].get_str(), "T_G");
            adaptor.T_H = ParsePoint33(request.params[4].get_str(), "T_H");
            auto dleq_t = ParseBlob<par::DLEQProof>(request.params[5].get_str());
            if (!dleq_t) throw JSONRPCError(RPC_INVALID_PARAMETER, "dleq_t must be serialized DLEQProof hex");

            const UniValue& xs_arr = request.params[6];
            const UniValue& zs_arr = request.params[7];
            if (!xs_arr.isArray() || xs_arr.size() < 2
                || !zs_arr.isArray() || zs_arr.size() != xs_arr.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "X_pub_shares + Z_pub_shares must be matching arrays of >=2 entries");
            }
            std::vector<::pricoin::ringsig::Point> X_pub_shares, Z_pub_shares;
            X_pub_shares.reserve(xs_arr.size());
            Z_pub_shares.reserve(zs_arr.size());
            for (size_t i = 0; i < xs_arr.size(); ++i) {
                X_pub_shares.push_back(ParsePoint33(xs_arr[i].get_str(), "X_pub_share"));
                Z_pub_shares.push_back(ParsePoint33(zs_arr[i].get_str(), "Z_pub_share"));
            }

            const UniValue& shares_arr = request.params[8];
            if (!shares_arr.isArray() || shares_arr.size() != xs_arr.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "shares.size() must match X_pub_shares.size()");
            }
            std::vector<pajr::AdaptorNonceShareML> shares;
            shares.reserve(shares_arr.size());
            for (size_t i = 0; i < shares_arr.size(); ++i) {
                const UniValue& s = shares_arr[i];
                pajr::AdaptorNonceShareML ns;
                std::memset(ns.alpha.data(), 0, ns.alpha.size());
                ns.L_share     = ParsePoint33(s["L_share"].get_str(), "L_share");
                ns.R_share     = ParsePoint33(s["R_share"].get_str(), "R_share");
                ns.KI_share    = ParsePoint33(s["KI_share"].get_str(), "KI_share");
                ns.D_share     = ParsePoint33(s["D_share"].get_str(), "D_share");
                auto dla = ParseBlob<par::DLEQProof>(s["dleq_alpha"].get_str());
                auto dlx = ParseBlob<par::DLEQProof>(s["dleq_x"].get_str());
                auto dlz = ParseBlob<par::DLEQProof>(s["dleq_z"].get_str());
                if (!dla || !dlx || !dlz) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "shares[i].dleq_* must be serialized DLEQProof hex");
                }
                ns.dleq_alpha = *dla;
                ns.dleq_x     = *dlx;
                ns.dleq_z     = *dlz;
                ns.commitment = ParseScalar32(s["commitment"].get_str(), "commitment");
                shares.push_back(ns);
            }

            auto label   = ParseSessionLabel(request.params[9],  "session_label");
            auto payload = ParseSessionLabel(request.params[10], "session_payload");

            auto combined = pajr::CombineAndWalkML(
                std::span<const ::pricoin::ringsig::MultiLayerMember>{ring},
                pi, msg, adaptor, *dleq_t,
                std::span<const ::pricoin::ringsig::Point>{X_pub_shares},
                std::span<const ::pricoin::ringsig::Point>{Z_pub_shares},
                std::span<const pajr::AdaptorNonceShareML>{shares},
                ToBytesSpan(label), ToBytesSpan(payload));
            if (!combined) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "CombineAndWalkML failed (DLEQ verify, commitment mismatch, or ring walk error)");

            UniValue s_others{UniValue::VARR};
            for (const auto& s : combined->s_others) s_others.push_back(ScalarHex(s));

            UniValue out{UniValue::VOBJ};
            out.pushKV("KI",      PointHex(combined->KI));
            out.pushKV("D",       PointHex(combined->D));
            out.pushKV("L_pi",    PointHex(combined->L_pi));
            out.pushKV("R_pi",    PointHex(combined->R_pi));
            out.pushKV("L_prime", PointHex(combined->L_prime));
            out.pushKV("R_prime", PointHex(combined->R_prime));
            out.pushKV("mu_P",    ScalarHex(combined->mu_P));
            out.pushKV("mu_C",    ScalarHex(combined->mu_C));
            out.pushKV("c_pi",    ScalarHex(combined->c_pi));
            out.pushKV("c0",      ScalarHex(combined->c0));
            out.pushKV("s_others", std::move(s_others));
            return out;
        }
    };
}

RPCMethod pricoin_jointspend_adaptor_assemble_ml()
{
    return RPCMethod{
        "pricoin_jointspend_adaptor_assemble_ml",
        "Multi-layer adaptor assemble — like adaptor_assemble, plus the\n"
        "joint D point and μ scalars so the resulting AdaptorPreSignature\n"
        "carries the commitment_image VerifyMultiLayer requires.\n",
        {
            {"KI",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"D",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Joint D point from combine_ml"},
            {"L_pi",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"R_pi",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"L_prime",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"R_prime",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"mu_P",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"mu_C",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"c_pi",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"c0",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"s_others",      RPCArg::Type::ARR,     RPCArg::Optional::NO, "",
                {{"s", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"close_shares",  RPCArg::Type::ARR,     RPCArg::Optional::NO, "",
                {{"s", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"pi",            RPCArg::Type::NUM,     RPCArg::Optional::NO, ""},
            {"T_G",           RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"T_H",           RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"dleq_t",        RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "presig", "Serialized AdaptorPreSignature with commitment_image set"}}
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_adaptor_assemble_ml", "<args>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            using namespace adaptor_helpers;

            pajr::AdaptorCombineOutputML combined;
            combined.KI      = ParsePoint33(request.params[0].get_str(), "KI");
            combined.D       = ParsePoint33(request.params[1].get_str(), "D");
            combined.L_pi    = ParsePoint33(request.params[2].get_str(), "L_pi");
            combined.R_pi    = ParsePoint33(request.params[3].get_str(), "R_pi");
            combined.L_prime = ParsePoint33(request.params[4].get_str(), "L_prime");
            combined.R_prime = ParsePoint33(request.params[5].get_str(), "R_prime");
            combined.mu_P    = ParseScalar32(request.params[6].get_str(), "mu_P");
            combined.mu_C    = ParseScalar32(request.params[7].get_str(), "mu_C");
            combined.c_pi    = ParseScalar32(request.params[8].get_str(), "c_pi");
            combined.c0      = ParseScalar32(request.params[9].get_str(), "c0");
            combined.s_others = ParseScalarArray(request.params[10], "s_others");

            const auto close_shares = ParseScalarArray(request.params[11], "close_shares");
            const size_t pi = static_cast<size_t>(request.params[12].getInt<int>());

            par::AdaptorPoints adaptor;
            adaptor.T_G = ParsePoint33(request.params[13].get_str(), "T_G");
            adaptor.T_H = ParsePoint33(request.params[14].get_str(), "T_H");
            auto dleq_t = ParseBlob<par::DLEQProof>(request.params[15].get_str());
            if (!dleq_t) throw JSONRPCError(RPC_INVALID_PARAMETER, "dleq_t must be serialized DLEQProof hex");

            auto presig = pajr::AssembleAdaptorPreSigML(combined,
                std::span<const ::pricoin::ringsig::Scalar>{close_shares},
                pi, adaptor, *dleq_t);
            if (!presig) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "AssembleAdaptorPreSigML failed");

            UniValue out{UniValue::VOBJ};
            out.pushKV("presig", HexStr(SerializeBlob(*presig)));
            return out;
        }
    };
}

RPCMethod pricoin_jointspend_adaptor_verify_presig()
{
    return RPCMethod{
        "pricoin_jointspend_adaptor_verify_presig",
        "Off-chain verify of an AdaptorPreSignature against a ring + msg.\n",
        {
            {"ring", RPCArg::Type::ARR, RPCArg::Optional::NO, "",
                {{"P", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"presig",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Serialized AdaptorPreSignature"},
            {"msg",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"session_label",   RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
            {"session_payload", RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "valid", ""}}
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_adaptor_verify_presig", "<args>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            using namespace adaptor_helpers;
            auto ring = ParseRing(request.params[0]);
            auto presig = ParseBlob<par::AdaptorPreSignature>(request.params[1].get_str());
            if (!presig) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "presig must be valid serialized AdaptorPreSignature hex");
            const auto msg_scalar = ParseScalar32(request.params[2].get_str(), "msg");
            uint256 msg;
            std::copy(msg_scalar.begin(), msg_scalar.end(), msg.begin());
            auto label   = ParseSessionLabel(request.params[3], "session_label");
            auto payload = ParseSessionLabel(request.params[4], "session_payload");
            const bool ok = par::VerifyPreSignature(
                std::span<const ::pricoin::ringsig::Point>{ring}, *presig, msg,
                ToBytesSpan(label), ToBytesSpan(payload));
            UniValue out{UniValue::VOBJ};
            out.pushKV("valid", ok);
            return out;
        }
    };
}

RPCMethod pricoin_jointspend_adaptor_adapt()
{
    return RPCMethod{
        "pricoin_jointspend_adaptor_adapt",
        "Adapt the pre-signature with the held secret t. Output is a standard\n"
        "CLSAG Signature blob, broadcastable on-chain. Verifies before returning\n"
        "(per spec §3.3 — t·G == T_G, s_pi != 0, full Verify under msg).\n",
        {
            {"presig", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"t",      RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte adaptor secret"},
            {"ring",   RPCArg::Type::ARR,     RPCArg::Optional::NO, "",
                {{"P", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"msg",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "sig", "Serialized Signature bytes"}}
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_adaptor_adapt", "<presig> <t> <ring> <msg>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            using namespace adaptor_helpers;
            auto presig = ParseBlob<par::AdaptorPreSignature>(request.params[0].get_str());
            if (!presig) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "presig must be serialized AdaptorPreSignature hex");
            auto t = ParseScalar32(request.params[1].get_str(), "t");
            auto ring = ParseRing(request.params[2]);
            const auto msg_scalar = ParseScalar32(request.params[3].get_str(), "msg");
            uint256 msg;
            std::copy(msg_scalar.begin(), msg_scalar.end(), msg.begin());
            auto sig = par::Adapt(*presig, t,
                std::span<const ::pricoin::ringsig::Point>{ring}, msg);
            if (!sig) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Adapt failed (wrong t, degenerate s_pi, or post-Verify mismatch)");
            UniValue out{UniValue::VOBJ};
            out.pushKV("sig", HexStr(SerializeBlob(*sig)));
            return out;
        }
    };
}

RPCMethod pricoin_jointspend_adaptor_extract()
{
    return RPCMethod{
        "pricoin_jointspend_adaptor_extract",
        "Extract t = sig.s[pi] - presig.s[pi] (mod n) from an on-chain CLSAG\n"
        "signature given the held pre-sig. Verifies t·G == T_G AND t·H_p(P_pi)\n"
        "== T_H per spec §3.5; returns nullopt on either check failure.\n",
        {
            {"ring",   RPCArg::Type::ARR,     RPCArg::Optional::NO, "",
                {{"P", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"presig", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"sig",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "t", "32-byte recovered scalar"}}
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_adaptor_extract", "<ring> <presig> <sig>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace js_helpers;
            using namespace adaptor_helpers;
            auto ring   = ParseRing(request.params[0]);
            auto presig = ParseBlob<par::AdaptorPreSignature>(request.params[1].get_str());
            auto sig    = ParseBlob<::pricoin::ringsig::Signature>(request.params[2].get_str());
            if (!presig || !sig) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "presig and sig must be serialized hex");
            auto t = par::Extract(
                std::span<const ::pricoin::ringsig::Point>{ring}, *presig, *sig);
            if (!t) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Extract failed (t·G != T_G or t·H_p(P_pi) != T_H)");
            UniValue out{UniValue::VOBJ};
            out.pushKV("t", ScalarHex(*t));
            return out;
        }
    };
}

} // namespace

void RegisterPricoinCTRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"pricoin", &pricoin_ct_send},
        {"pricoin", &pricoin_jointspend_round1},
        {"pricoin", &pricoin_jointspend_combine},
        {"pricoin", &pricoin_jointspend_share},
        {"pricoin", &pricoin_jointspend_assemble},
        {"pricoin", &pricoin_jointspend_verify},
        {"pricoin", &pricoin_pubkey_from_scalar},
        {"pricoin", &pricoin_adaptor_compute_points},
        {"pricoin", &pricoin_adaptor_dleq_prove},
        {"pricoin", &pricoin_adaptor_dleq_verify},
        {"pricoin", &pricoin_jointspend_adaptor_round1},
        {"pricoin", &pricoin_jointspend_adaptor_combine},
        {"pricoin", &pricoin_jointspend_adaptor_assemble},
        {"pricoin", &pricoin_jointspend_adaptor_round1_ml},
        {"pricoin", &pricoin_jointspend_adaptor_combine_ml},
        {"pricoin", &pricoin_jointspend_adaptor_assemble_ml},
        {"pricoin", &pricoin_jointspend_adaptor_verify_presig},
        {"pricoin", &pricoin_jointspend_adaptor_adapt},
        {"pricoin", &pricoin_jointspend_adaptor_extract},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
