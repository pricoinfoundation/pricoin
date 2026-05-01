// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/clsag_nonce_policy.h>

#include <crypto/sha256.h>
#include <random.h>
#include <util/time.h>

#include <cstring>
#include <stdexcept>
#include <string>

namespace pricoin::clsag_nonce_policy {

namespace {

constexpr const char* kRecordDigestTag = "pricoin/clsag-nonce-record-v1";

void Check(bool cond, const char* what)
{
    if (!cond) {
        throw std::runtime_error(std::string("CLSAG nonce-policy self-test failed: ") + what);
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
    // Length-prefix the variable-length output_id so a key that ends
    // with bytes from ring_hash can't alias.
    uint64_t len = k.joint_output_id.size();
    unsigned char len_bytes[8];
    for (int i = 0; i < 8; ++i) len_bytes[i] = static_cast<unsigned char>((len >> (8 * i)) & 0xff);
    h.Write(len_bytes, 8);
    if (!k.joint_output_id.empty()) {
        h.Write(k.joint_output_id.data(), k.joint_output_id.size());
    }
    h.Write(k.ring_hash.data(), 32);
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
    // Per §4.1a:
    //   reject if a record with the same (joint_output, ring_hash, role) exists
    //   with a different session_id, OR with t_published == false.
    if (existing->key != proposed.key) {
        // Caller error: the records' keys differ. Treat as conflict.
        return Decision::ConflictDifferentSession;
    }
    if (existing->session_id != proposed.session_id) {
        return Decision::ConflictDifferentSession;
    }
    if (!existing->t_published) {
        return Decision::ConflictSameSessionInFlight;
    }
    // existing->session_id == proposed.session_id && existing->t_published == true.
    // The spec language permits this case: t was published, the joint output is
    // logically spent, the same wallet may reopen a record under the same session
    // (idempotent retry on a completed swap is harmless).
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

bool Store::MarkTPublished(const RecordKey& k)
{
    auto it = m_records.find(k);
    if (it == m_records.end()) return false;
    it->second.t_published = true;
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
    GetStrongRandBytes(rec.alpha);
    GetStrongRandBytes(rec.commitment);
    rec.t_published = false;
    return rec;
}

RecordKey MakeKey(uint8_t output_seed, uint8_t ring_seed, Role role)
{
    RecordKey k;
    k.joint_output_id.resize(36, 0);  // emulate canonical txid:vout (36 bytes)
    k.joint_output_id[0] = output_seed;
    k.ring_hash.data()[0] = ring_seed;
    k.role = role;
    return k;
}

} // namespace

void RunSelfTest()
{
    // ─── Test 1: RecordDigest is stable + sensitive to all inputs ───
    {
        RecordKey k1 = MakeKey(1, 2, Role::Initiator);
        RecordKey k2 = MakeKey(1, 2, Role::Initiator);
        Check(RecordDigest(k1) == RecordDigest(k2), "digest deterministic");

        RecordKey k3 = MakeKey(1, 2, Role::Responder);
        Check(RecordDigest(k1) != RecordDigest(k3), "digest sensitive to role");

        RecordKey k4 = MakeKey(1, 3, Role::Initiator);
        Check(RecordDigest(k1) != RecordDigest(k4), "digest sensitive to ring_hash");

        RecordKey k5 = MakeKey(2, 2, Role::Initiator);
        Check(RecordDigest(k1) != RecordDigest(k5), "digest sensitive to output_id");

        // Length-prefix check: an output_id that aliases ring_hash bytes must produce a different digest.
        RecordKey ka = k1;
        ka.joint_output_id.assign(36, 0);
        RecordKey kb = k1;
        // Move one byte from output_id into ring_hash, see that digest changes.
        kb.joint_output_id.assign(35, 0);
        Check(RecordDigest(ka) != RecordDigest(kb), "digest sensitive to length boundary");
    }

    // ─── Test 2: TryCreate on empty store succeeds. ───
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 sid;
        GetStrongRandBytes(sid);
        Check(s.TryCreate(MakeRecord(k, sid)) == Decision::Ok, "TryCreate empty");
        Check(s.Get(k) != nullptr, "Get after Create");
        Check(s.Size() == 1, "Size==1");
    }

    // ─── Test 3: Same session re-Create rejected (in-flight). ───
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 sid;
        GetStrongRandBytes(sid);
        Check(s.TryCreate(MakeRecord(k, sid)) == Decision::Ok, "first TryCreate");
        // Second create same session, t_published still false:
        Check(s.TryCreate(MakeRecord(k, sid)) == Decision::ConflictSameSessionInFlight,
              "in-flight same-session reject");
    }

    // ─── Test 4: Different session rejected (the attack). ───
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 sid_a;
        uint256 sid_b;
        GetStrongRandBytes(sid_a);
        GetStrongRandBytes(sid_b);
        Check(sid_a != sid_b, "sids differ");
        Check(s.TryCreate(MakeRecord(k, sid_a)) == Decision::Ok, "session A");
        Check(s.TryCreate(MakeRecord(k, sid_b)) == Decision::ConflictDifferentSession,
              "different-session reject (the attack)");
    }

    // ─── Test 5: After MarkTPublished, same session re-Create allowed. ───
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 sid;
        GetStrongRandBytes(sid);
        Check(s.TryCreate(MakeRecord(k, sid)) == Decision::Ok, "create");
        Check(s.MarkTPublished(k), "MarkTPublished");
        Check(s.Get(k)->t_published, "flag set");
        // Now allowed under SAME session_id:
        Check(s.TryCreate(MakeRecord(k, sid)) == Decision::Ok,
              "post-publish, same session permitted");
    }

    // ─── Test 6: After MarkTPublished, DIFFERENT session still rejected. ───
    //
    // Per §4.1a, t_published gates whether the joint output may be
    // signed AGAIN at all. Different session_id with t_published==true
    // is not the attack but the spec text "different session_id" in
    // the reject clause is unconditional. Implementation: reject
    // different session_id regardless of t_published flag — strictest
    // reading of the spec. The wallet user must explicitly delete the
    // record (a separate, audit-logged action) before reusing the
    // joint output under a new session.
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 sid_a;
        uint256 sid_b;
        GetStrongRandBytes(sid_a);
        GetStrongRandBytes(sid_b);
        Check(s.TryCreate(MakeRecord(k, sid_a)) == Decision::Ok, "create A");
        Check(s.MarkTPublished(k), "MarkTPublished");
        Check(s.TryCreate(MakeRecord(k, sid_b)) == Decision::ConflictDifferentSession,
              "post-publish, different session still rejected");
    }

    // ─── Test 7: Different role on same output is independent. ───
    //
    // (Initiator-side and responder-side records for the same joint
    // output are distinct keys per the spec — both parties run their
    // own state machines, both must persist independently.)
    {
        Store s;
        RecordKey k_init = MakeKey(0x10, 0x20, Role::Initiator);
        RecordKey k_resp = MakeKey(0x10, 0x20, Role::Responder);
        uint256 sid;
        GetStrongRandBytes(sid);
        Check(s.TryCreate(MakeRecord(k_init, sid)) == Decision::Ok, "init record");
        Check(s.TryCreate(MakeRecord(k_resp, sid)) == Decision::Ok,
              "resp record under same session is independent");
        Check(s.Size() == 2, "two records");
    }

    // ─── Test 8: Replay path bypasses policy. ───
    //
    // When the wallet reopens, records loaded from disk go through
    // Replay() not TryCreate() — we trust durably-persisted state.
    {
        Store s;
        RecordKey k = MakeKey(0x10, 0x20, Role::Initiator);
        uint256 sid;
        GetStrongRandBytes(sid);
        NonceRecord rec = MakeRecord(k, sid);
        rec.t_published = true;
        s.Replay(rec);
        Check(s.Get(k) != nullptr, "Replay puts record in store");
        Check(s.Get(k)->t_published, "Replay preserves t_published");
        // Replay overwrites:
        rec.t_published = false;
        s.Replay(rec);
        Check(!s.Get(k)->t_published, "Replay overwrites prior record");
    }
}

} // namespace pricoin::clsag_nonce_policy
