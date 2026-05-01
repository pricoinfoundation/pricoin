// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/btc_musig2_nonce_policy.h>

#include <crypto/sha256.h>
#include <random.h>
#include <util/time.h>

#include <cstring>
#include <stdexcept>
#include <string>

namespace pricoin::btc_musig2_nonce_policy {

namespace {

constexpr const char* kRecordDigestTag = "pricoin/btc-musig2-nonce-record-v1";

void Check(bool cond, const char* what)
{
    if (!cond) {
        throw std::runtime_error(std::string("BTC MuSig2 nonce-policy self-test failed: ") + what);
    }
}

int64_t NowSec()
{
    return GetTime<std::chrono::seconds>().count();
}

} // namespace

uint256 RecordDigest(const RecordKey& k)
{
    CSHA256 h;
    h.Write(reinterpret_cast<const unsigned char*>(kRecordDigestTag),
            std::strlen(kRecordDigestTag));
    h.Write(k.agg_xonly.data(), 32);
    h.Write(k.msg.data(), 32);
    unsigned char role_byte = static_cast<unsigned char>(k.role);
    h.Write(&role_byte, 1);
    uint256 out;
    h.Finalize(out.data());
    return out;
}

Decision EvaluateCreate(
    const std::optional<NonceRecord>& existing,
    const NonceRecord& proposed)
{
    if (!existing) return Decision::Ok;
    if (existing->key != proposed.key) {
        // Caller error.
        return Decision::ConflictDifferentSession;
    }
    if (existing->session_id != proposed.session_id) {
        return Decision::ConflictDifferentSession;
    }
    if (!existing->finalized) {
        return Decision::ConflictSameSessionInFlight;
    }
    // Same session_id and existing.finalized — slot is logically free.
    return Decision::Ok;
}

void Store::Replay(NonceRecord rec)
{
    m_records[rec.key] = std::move(rec);
}

Decision Store::TryCreate(NonceRecord rec)
{
    auto it = m_records.find(rec.key);
    std::optional<NonceRecord> existing;
    if (it != m_records.end()) existing = it->second;
    Decision d = EvaluateCreate(existing, rec);
    if (d != Decision::Ok) return d;

    if (rec.created_time == 0) rec.created_time = NowSec();
    rec.updated_time = rec.created_time;
    m_records[rec.key] = std::move(rec);
    return Decision::Ok;
}

bool Store::MarkFinalized(const RecordKey& k)
{
    auto it = m_records.find(k);
    if (it == m_records.end()) return false;
    it->second.finalized = true;
    it->second.updated_time = NowSec();
    return true;
}

const NonceRecord* Store::Get(const RecordKey& k) const
{
    auto it = m_records.find(k);
    if (it == m_records.end()) return nullptr;
    return &it->second;
}

bool Store::Erase(const RecordKey& k)
{
    return m_records.erase(k) > 0;
}

void Store::ForEach(const std::function<void(const NonceRecord&)>& f) const
{
    for (const auto& [_, rec] : m_records) f(rec);
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

namespace {

NonceRecord MakeRecord(const RecordKey& k, const uint256& sid)
{
    NonceRecord rec;
    rec.key = k;
    rec.session_id = sid;
    // pubnonce is opaque content for the policy layer — fill with two
    // 32-byte chunks (GetStrongRandBytes is capped at 32 per call) plus
    // a 2-byte tail, just to exercise non-zero data.
    std::array<unsigned char, 32> chunk1, chunk2;
    GetStrongRandBytes(chunk1);
    GetStrongRandBytes(chunk2);
    std::copy(chunk1.begin(), chunk1.end(), rec.pubnonce.begin());
    std::copy(chunk2.begin(), chunk2.end(), rec.pubnonce.begin() + 32);
    rec.pubnonce[64] = chunk1[0];
    rec.pubnonce[65] = chunk2[0];
    rec.finalized = false;
    return rec;
}

RecordKey MakeKey(uint8_t agg_seed, uint8_t msg_seed, Role role)
{
    RecordKey k;
    k.agg_xonly.data()[0] = agg_seed;
    k.msg.data()[0] = msg_seed;
    k.role = role;
    return k;
}

} // namespace

void RunSelfTest()
{
    // ─── Test 1: digest is sensitive to all inputs ───
    {
        RecordKey k1 = MakeKey(1, 2, Role::Initiator);
        RecordKey k2 = MakeKey(1, 2, Role::Initiator);
        Check(RecordDigest(k1) == RecordDigest(k2), "digest deterministic");

        RecordKey k3 = MakeKey(1, 2, Role::Responder);
        Check(RecordDigest(k1) != RecordDigest(k3), "digest sensitive to role");

        RecordKey k4 = MakeKey(1, 3, Role::Initiator);
        Check(RecordDigest(k1) != RecordDigest(k4), "digest sensitive to msg");

        RecordKey k5 = MakeKey(2, 2, Role::Initiator);
        Check(RecordDigest(k1) != RecordDigest(k5), "digest sensitive to agg_xonly");
    }

    // ─── Test 2: empty store + first create ───
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 sid;
        GetStrongRandBytes(sid);
        Check(s.TryCreate(MakeRecord(k, sid)) == Decision::Ok, "first TryCreate");
        Check(s.Get(k) != nullptr, "Get after Create");
    }

    // ─── Test 3: same session in-flight reject ───
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 sid;
        GetStrongRandBytes(sid);
        Check(s.TryCreate(MakeRecord(k, sid)) == Decision::Ok, "first");
        Check(s.TryCreate(MakeRecord(k, sid)) == Decision::ConflictSameSessionInFlight,
              "in-flight same-session reject");
    }

    // ─── Test 4: different session reject (the attack) ───
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 a, b;
        GetStrongRandBytes(a);
        GetStrongRandBytes(b);
        Check(a != b, "sids differ");
        Check(s.TryCreate(MakeRecord(k, a)) == Decision::Ok, "create A");
        Check(s.TryCreate(MakeRecord(k, b)) == Decision::ConflictDifferentSession,
              "different-session reject (the attack)");
    }

    // ─── Test 5: finalized → same session permitted ───
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 sid;
        GetStrongRandBytes(sid);
        Check(s.TryCreate(MakeRecord(k, sid)) == Decision::Ok, "create");
        Check(s.MarkFinalized(k), "MarkFinalized");
        Check(s.Get(k)->finalized, "flag set");
        Check(s.TryCreate(MakeRecord(k, sid)) == Decision::Ok,
              "post-finalize, same session permitted");
    }

    // ─── Test 6: finalized → different session still rejected ───
    // Strict reading: different session_id is unconditionally rejected
    // while a record exists. Operator must explicitly Erase first.
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 a, b;
        GetStrongRandBytes(a);
        GetStrongRandBytes(b);
        Check(s.TryCreate(MakeRecord(k, a)) == Decision::Ok, "create A");
        Check(s.MarkFinalized(k), "finalize");
        Check(s.TryCreate(MakeRecord(k, b)) == Decision::ConflictDifferentSession,
              "post-finalize, different session still rejected");
    }

    // ─── Test 7: role independence ───
    {
        Store s;
        RecordKey ki = MakeKey(0x10, 0x20, Role::Initiator);
        RecordKey kr = MakeKey(0x10, 0x20, Role::Responder);
        uint256 sid;
        GetStrongRandBytes(sid);
        Check(s.TryCreate(MakeRecord(ki, sid)) == Decision::Ok, "init");
        Check(s.TryCreate(MakeRecord(kr, sid)) == Decision::Ok,
              "resp role independent");
        Check(s.Size() == 2, "two records");
    }

    // ─── Test 8: Replay bypasses policy ───
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 sid;
        GetStrongRandBytes(sid);
        NonceRecord rec = MakeRecord(k, sid);
        rec.finalized = true;
        s.Replay(rec);
        Check(s.Get(k) != nullptr, "Replay puts record in store");
        Check(s.Get(k)->finalized, "Replay preserves finalized");
        rec.finalized = false;
        s.Replay(rec);
        Check(!s.Get(k)->finalized, "Replay overwrites prior");
    }

    // ─── Test 9: Erase clears slot, fresh session permitted ───
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 a, b;
        GetStrongRandBytes(a);
        GetStrongRandBytes(b);
        Check(s.TryCreate(MakeRecord(k, a)) == Decision::Ok, "create A");
        Check(s.Erase(k), "erase");
        Check(s.Get(k) == nullptr, "gone");
        Check(s.TryCreate(MakeRecord(k, b)) == Decision::Ok,
              "post-erase fresh session permitted");
    }
}

} // namespace pricoin::btc_musig2_nonce_policy
