// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SWAP_ATOMIC_SWAP_E2E_TEST_H
#define BITCOIN_SWAP_ATOMIC_SWAP_E2E_TEST_H

// Atomic-swap end-to-end cryptographic integration test.
//
// Walks one full happy-path swap in a single process, using the
// real crypto primitives (no mocks). Validates the cross-chain
// binding that ties the BTC and PRIC legs together: a single
// adaptor secret t, encoded as a 33-byte compressed point T_G,
// embedded in BOTH a PRIC adaptor-CLSAG pre-signature and a BTC
// MuSig2 + adaptor pre-signature. When Bob spends the PRIC joint
// output, t is extractable on-chain; Alice extracts it and adapts
// the BTC pre-sig, claiming her BTC.
//
// This test is what the full atomic-swap orchestration (state
// machine + persistence + RPCs, in a follow-up commit) will drive
// in production. Running it on every daemon startup catches any
// regression in any of the underlying primitives that would break
// the cross-chain composition.
//
// What this test does NOT cover:
//   * Refund-tx pre-signing flow (timelock + non-adaptor cooperative
//     sigs) — exercised separately when the orchestration layer lands.
//   * On-chain confirmation, mempool, reorg handling — orchestration.
//   * Wallet persistence of pre-sigs — orchestration.
//   * Identifiable-abort blame tickets — orchestration.

namespace pricoin::swap::atomic_swap_e2e_test {

// Self-test. Throws std::runtime_error on any failure. Wired into
// the daemon-startup self-test runner in pricoin/ct.cpp.
void RunSelfTest();

} // namespace pricoin::swap::atomic_swap_e2e_test

#endif // BITCOIN_SWAP_ATOMIC_SWAP_E2E_TEST_H
