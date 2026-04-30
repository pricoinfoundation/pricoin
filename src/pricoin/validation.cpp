// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/validation.h>

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <hash.h>
#include <pricoin/ct.h>
#include <pricoin/cttx.h>
#include <pricoin/ringsig.h>
#include <primitives/transaction.h>
#include <logging.h>
#include <secp256k1.h>
#include <secp256k1_generator.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/fs.h>

#include <fstream>
#include <unordered_set>

namespace pricoin {

namespace {

// On-disk key-image store. Every confirmed v4 ring spend's key image is
// committed here; queries against the in-memory set drive forward
// double-spend detection (mempool + ConnectBlock) and the wallet's
// "is this output already spent?" check.
//
// File format (v2, magic-prefixed):
//   bytes 0..3   : magic "PKI\x01"
//   then a sequence of per-block entries:
//     [block_hash : 32 little-endian-as-uint256]
//     [num_kis    : uint32 little-endian]
//     [ki         : 33 bytes]*num_kis
//
// Per-block entries let DisconnectBlock cleanly undo on a reorg: we look
// up the block, drop its KIs from the in-memory set, and rewrite the
// file. (The previous append-only format had no block tagging, so a
// reorg either left stale KIs in memory or — after restart, when KIs
// reloaded from the file — silently rejected the corrected chain as
// "double-spend" of its own KIs.)
//
// Format v1 (legacy, pre-block-tagging): raw 33-byte KIs concatenated,
// no header. Read-supported for one-time migration; on first new commit
// the file is rewritten in v2 format. KIs read from a v1 file are
// stored under a sentinel "unknown block" bucket — they're detected as
// committed (forward correctness) but never removed by UncommitBlockKIs
// (we don't know which block to attribute them to). This is no worse
// than the prior behaviour; new activity is reorg-safe.
struct KIHash {
    size_t operator()(const ringsig::Point& p) const noexcept {
        // First 8 bytes of the compressed pubkey are already uniformly distributed.
        size_t h = 0;
        std::memcpy(&h, p.data(), sizeof(h));
        return h;
    }
};
constexpr unsigned char kKIFileMagic[4] = {'P', 'K', 'I', 0x01};
constexpr size_t kKISize = 33;

Mutex g_ki_mutex;
std::unordered_set<ringsig::Point, KIHash> g_key_images GUARDED_BY(g_ki_mutex);
// block_hash → KIs that block committed. Used by UncommitBlockKIs.
// Entries under uint256{} (the all-zero hash) are legacy KIs whose
// containing block was lost on the v1→v2 migration; they are never
// removed by UncommitBlockKIs because we can't attribute them.
std::map<uint256, std::vector<ringsig::Point>> g_kis_by_block GUARDED_BY(g_ki_mutex);
fs::path g_ki_path GUARDED_BY(g_ki_mutex);

void WriteEntry(std::ofstream& f, const uint256& block_hash,
                std::span<const ringsig::Point> kis)
{
    f.write(reinterpret_cast<const char*>(block_hash.begin()), 32);
    const uint32_t n = static_cast<uint32_t>(kis.size());
    unsigned char le[4]{
        static_cast<unsigned char>(n & 0xff),
        static_cast<unsigned char>((n >> 8) & 0xff),
        static_cast<unsigned char>((n >> 16) & 0xff),
        static_cast<unsigned char>((n >> 24) & 0xff),
    };
    f.write(reinterpret_cast<const char*>(le), 4);
    for (const auto& ki : kis) {
        f.write(reinterpret_cast<const char*>(ki.data()), ki.size());
    }
}

// Append one block's entry to the persistent file. Caller has g_ki_mutex.
void AppendBlockEntry(const uint256& block_hash,
                      std::span<const ringsig::Point> kis)
    EXCLUSIVE_LOCKS_REQUIRED(g_ki_mutex)
{
    if (g_ki_path.empty()) return;
    std::ofstream f(fs::PathToString(g_ki_path), std::ios::binary | std::ios::app);
    if (!f) return;
    WriteEntry(f, block_hash, kis);
}

// Rewrite the entire file from in-memory state. Used on disconnect (and
// on first commit after a v1→v2 migration, where the file lacks the
// magic header). Atomic-ish via tmp + rename.
void RewriteFile() EXCLUSIVE_LOCKS_REQUIRED(g_ki_mutex)
{
    if (g_ki_path.empty()) return;
    fs::path tmp = g_ki_path;
    tmp += ".tmp";
    {
        std::ofstream f(fs::PathToString(tmp), std::ios::binary | std::ios::trunc);
        if (!f) return;
        f.write(reinterpret_cast<const char*>(kKIFileMagic), sizeof(kKIFileMagic));
        for (const auto& [block_hash, kis] : g_kis_by_block) {
            if (kis.empty()) continue;
            WriteEntry(f, block_hash, kis);
        }
        if (!f.good()) {
            fs::remove(tmp);
            return;
        }
    }
    std::error_code ec;
    fs::rename(tmp, g_ki_path, ec);
    if (ec) {
        LogWarning("Pricoin: failed to rename %s -> %s (%s)",
                   fs::PathToString(tmp), fs::PathToString(g_ki_path), ec.message());
    }
}

// Compute the message that ring sigs commit to: the tx serialized without
// witness AND with all ring-sig fields zeroed out so the sig binds to the
// tx fields without being reflexive.
uint256 ComputeRingMessage(const CTransaction& tx)
{
    CMutableTransaction mtx{tx};
    for (auto& ri : mtx.ct_bundle.ring_inputs) {
        ri.sig = ringsig::Signature{};
    }
    HashWriter hw{};
    hw << TX_NO_WITNESS(CTransaction{std::move(mtx)});
    return hw.GetSHA256();
}

bool VerifyDirectInputs(
    const CTransaction& tx,
    const CCoinsViewCache& inputs,
    int nSpendHeight,
    TxValidationState& state)
{
    if (tx.vin.size() != tx.ct_bundle.input_commitments.size()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-input-count");
    }
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint& prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        if (coin.IsSpent()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-spent-prevout");
        }
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }
        ct::Commitment expected{};
        if (coin.IsConfidential()) {
            expected = coin.commitment;
        } else {
            if (!MoneyRange(coin.out.nValue)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputvalues-outofrange");
            }
            ct::BlindingFactor zero_blind{};
            auto built = ct::Commitment::Create(static_cast<uint64_t>(coin.out.nValue), zero_blind);
            if (!built) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-input-commit-construction");
            }
            expected = *built;
        }
        if (expected != tx.ct_bundle.input_commitments[i]) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-input-commit-mismatch",
                strprintf("vin[%u] claims input commitment that does not match prev output", i));
        }
    }
    return true;
}

bool VerifyRingInputs(
    const CTransaction& tx,
    const CCoinsViewCache& inputs,
    int nSpendHeight,
    TxValidationState& state,
    std::vector<ct::Commitment>& effective_input_commits)
{
    const uint256 msg = ComputeRingMessage(tx);
    for (size_t idx = 0; idx < tx.ct_bundle.ring_inputs.size(); ++idx) {
        const auto& ri = tx.ct_bundle.ring_inputs[idx];
        if (ri.ring.empty()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-empty-ring");
        }
        if (ri.sig.s.size() != ri.ring.size()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-sig-size");
        }
        // Ring members must reference distinct prev outputs. Otherwise the
        // CLSAG signature still verifies, but the effective anonymity set
        // shrinks below the announced ring size — a silent privacy leak.
        for (size_t a = 0; a < ri.ring.size(); ++a) {
            for (size_t b = a + 1; b < ri.ring.size(); ++b) {
                if (ri.ring[a] == ri.ring[b]) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-ring-duplicate");
                }
            }
        }

        // Phase 4c: multi-layer CLSAG. Build (P_i, W_i) pairs where
        // W_i = C_i − C_pseudo via the same prefix-swap conversion as the
        // signer. This binds the chosen ring member's commitment to the
        // pseudo (defeats the inflation attack possible with single-layer).
        std::vector<ringsig::MultiLayerMember> members(ri.ring.size());
        for (size_t k = 0; k < ri.ring.size(); ++k) {
            const COutPoint op{Txid::FromUint256(ri.ring[k].hash), ri.ring[k].n};
            const Coin& c = inputs.AccessCoin(op);
            // Phase 3a: v4 outputs are never erased from chainstate, so an
            // empty Coin here means the outpoint never existed. Spent-ness is
            // tracked exclusively by the key-image set; ring members may have
            // been spent in earlier ring txs and that's fine.
            if (c.IsSpent()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-ring-member-missing",
                    strprintf("ring[%u][%u]=%s:%u is not on chain",
                              (unsigned)idx, (unsigned)k, op.hash.ToString(), op.n));
            }
            if (!c.IsConfidential()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-ring-member-missing",
                    strprintf("ring[%u][%u] is not confidential", (unsigned)idx, (unsigned)k));
            }
            if (c.IsCoinBase() && nSpendHeight - c.nHeight < COINBASE_MATURITY) {
                return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-pct-ring-member-immature");
            }
            members[k].P = c.one_time_pubkey;
            auto W = ct::SubtractCommitments(c.commitment, ri.pseudo_commitment);
            if (!W) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-commit-delta");
            }
            members[k].W = *W;
        }

        // Key image must not be in the committed set.
        {
            LOCK(g_ki_mutex);
            if (g_key_images.contains(ri.sig.key_image)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-double-spend-keyimage");
            }
        }

        if (!ringsig::VerifyMultiLayer(std::span<const ringsig::MultiLayerMember>{members}, ri.sig, msg)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-ring-sig-invalid");
        }
        // Note: insertion into g_key_images happens only at block-connect via
        // CommitRingKeyImages(), so mempool-acceptance can be idempotent
        // (PreChecks may re-run validation) without rejecting our own tx.

        // The pseudo commitment is the input's contribution to the bundle's
        // tally — it's what the verifier sums in place of input_commitments[i].
        effective_input_commits.push_back(ri.pseudo_commitment);
    }
    return true;
}

} // namespace

bool VerifyConfidentialContextual(
    const CTransaction& tx,
    const CCoinsViewCache& inputs,
    int nSpendHeight,
    TxValidationState& state,
    CAmount& txfee_out)
{
    if (tx.version != PRICOIN_CT_VERSION) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-not-ct-version");
    }
    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
    }

    const bool has_direct = !tx.ct_bundle.input_commitments.empty();
    const bool has_ring = !tx.ct_bundle.ring_inputs.empty();
    if (has_direct && has_ring) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-mixed-input-modes");
    }
    if (!has_direct && !has_ring) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-no-inputs");
    }

    std::vector<ct::Commitment> effective_input_commits;
    if (has_direct) {
        if (!VerifyDirectInputs(tx, inputs, nSpendHeight, state)) return false;
        effective_input_commits = tx.ct_bundle.input_commitments;
    } else {
        if (!VerifyRingInputs(tx, inputs, nSpendHeight, state, effective_input_commits)) return false;
    }

    // Verify rangeproofs on outputs.
    for (const auto& out : tx.ct_bundle.outputs) {
        const std::span<const unsigned char> spk_span{out.script_pubkey};
        const std::span<const unsigned char> proof_span{out.rangeproof};
        if (!ct::VerifyRangeProof(out.commitment, proof_span, spk_span)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-rangeproof-invalid");
        }
    }
    // Verify tally with the effective input commitments + transparent fee.
    std::vector<ct::Commitment> out_commits;
    out_commits.reserve(tx.ct_bundle.outputs.size());
    for (const auto& o : tx.ct_bundle.outputs) out_commits.push_back(o.commitment);
    if (!ct::VerifySumZero(effective_input_commits, out_commits, tx.ct_bundle.transparent_fee)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-tally");
    }

    if (tx.ct_bundle.transparent_fee > static_cast<uint64_t>(MAX_MONEY)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-fee-toolarge");
    }
    txfee_out = static_cast<CAmount>(tx.ct_bundle.transparent_fee);
    return true;
}

void CommitBlockKIs(const uint256& block_hash,
                    std::span<const ringsig::Point> kis)
{
    if (kis.empty()) return;
    LOCK(g_ki_mutex);
    auto& bucket = g_kis_by_block[block_hash];
    std::vector<ringsig::Point> newly_added;
    newly_added.reserve(kis.size());
    for (const auto& ki : kis) {
        if (g_key_images.insert(ki).second) {
            bucket.push_back(ki);
            newly_added.push_back(ki);
        }
    }
    if (!newly_added.empty()) {
        AppendBlockEntry(block_hash, newly_added);
    }
}

void UncommitBlockKIs(const uint256& block_hash)
{
    LOCK(g_ki_mutex);
    auto it = g_kis_by_block.find(block_hash);
    if (it == g_kis_by_block.end()) return;
    for (const auto& ki : it->second) {
        g_key_images.erase(ki);
    }
    g_kis_by_block.erase(it);
    // Reorg out of a confirmed block: rewrite the file so the on-disk
    // state matches memory. A daemon restart at this point must NOT
    // reload the disconnected block's KIs.
    RewriteFile();
}

bool IsKeyImageCommitted(const ringsig::Point& ki)
{
    LOCK(g_ki_mutex);
    return g_key_images.contains(ki);
}

void InitKeyImageStore(const std::string& datadir_path)
{
    LOCK(g_ki_mutex);
    g_ki_path = fs::PathFromString(datadir_path) / "pricoin_keyimages.dat";
    std::ifstream f(fs::PathToString(g_ki_path), std::ios::binary);
    if (!f) {
        LogInfo("Pricoin: key-image store empty at startup (%s)", fs::PathToString(g_ki_path));
        return;
    }

    // Detect format: read the first 4 bytes; if they match the magic, it's
    // a v2 file with per-block entries. Otherwise treat the entire file as
    // a stream of raw 33-byte KIs (v1 legacy).
    unsigned char magic_buf[4]{};
    f.read(reinterpret_cast<char*>(magic_buf), 4);
    const bool is_v2 = (f.gcount() == 4 &&
                        std::memcmp(magic_buf, kKIFileMagic, 4) == 0);

    size_t loaded = 0;
    if (is_v2) {
        // Stream per-block entries: [block_hash:32][num_kis:u32][KIs:33*N].
        while (f) {
            uint256 block_hash;
            f.read(reinterpret_cast<char*>(block_hash.begin()), 32);
            if (f.gcount() == 0) break;  // clean EOF
            if (f.gcount() != 32) {
                LogWarning("Pricoin: truncated block_hash in key-image store");
                break;
            }
            unsigned char le[4]{};
            f.read(reinterpret_cast<char*>(le), 4);
            if (f.gcount() != 4) {
                LogWarning("Pricoin: truncated num_kis in key-image store");
                break;
            }
            const uint32_t n = static_cast<uint32_t>(le[0]) |
                               (static_cast<uint32_t>(le[1]) << 8) |
                               (static_cast<uint32_t>(le[2]) << 16) |
                               (static_cast<uint32_t>(le[3]) << 24);
            // Sanity bound: a single block shouldn't have more than a few
            // thousand KIs even pathologically. 1M is a safe ceiling that
            // also prevents trying to allocate a comically large vector
            // on file corruption.
            if (n > 1'000'000) {
                LogWarning("Pricoin: implausible KI count %u in entry — stopping load", n);
                break;
            }
            auto& bucket = g_kis_by_block[block_hash];
            bucket.reserve(bucket.size() + n);
            ringsig::Point ki;
            for (uint32_t i = 0; i < n; ++i) {
                f.read(reinterpret_cast<char*>(ki.data()), ki.size());
                if (f.gcount() != static_cast<std::streamsize>(ki.size())) {
                    LogWarning("Pricoin: truncated KI in entry — stopping load");
                    return;
                }
                if (g_key_images.insert(ki).second) {
                    bucket.push_back(ki);
                    ++loaded;
                }
            }
        }
        LogInfo("Pricoin: loaded %u key image(s) across %u block(s) from %s",
                (unsigned)loaded, (unsigned)g_kis_by_block.size(),
                fs::PathToString(g_ki_path));
    } else {
        // v1 legacy: rewind, stream raw 33-byte KIs into the "unknown
        // block" bucket. This bucket is forward-correctness only — KIs in
        // it are detected as committed but can't be removed by
        // UncommitBlockKIs (we don't know which block to attribute them
        // to). On the next CommitBlockKIs call the file gets rewritten in
        // v2 format with the legacy bucket preserved.
        f.clear();
        f.seekg(0);
        ringsig::Point ki;
        auto& legacy_bucket = g_kis_by_block[uint256{}];
        while (f.read(reinterpret_cast<char*>(ki.data()), ki.size())) {
            if (f.gcount() != static_cast<std::streamsize>(ki.size())) break;
            if (g_key_images.insert(ki).second) {
                legacy_bucket.push_back(ki);
                ++loaded;
            }
        }
        LogWarning("Pricoin: loaded %u legacy (untagged) key image(s) from %s — "
                   "deep reorgs across pre-upgrade blocks may leave stale entries; "
                   "new commits will rewrite this file in the v2 per-block format",
                   (unsigned)loaded, fs::PathToString(g_ki_path));
        // Rewrite immediately so the magic header lands on disk and future
        // restarts use the v2 path.
        RewriteFile();
    }
}

} // namespace pricoin
