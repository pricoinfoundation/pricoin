// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_WALLET_H
#define BITCOIN_INTERFACES_WALLET_H

#include <addresstype.h>
#include <common/signmessage.h>
#include <consensus/amount.h>
#include <interfaces/chain.h>
#include <primitives/transaction_identifier.h>
#include <pubkey.h>
#include <script/script.h>
#include <support/allocators/secure.h>
#include <util/fs.h>
#include <util/result.h>
#include <util/ui_change_type.h>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

class CFeeRate;
class CKey;
enum class FeeReason;
enum class OutputType;
struct PartiallySignedTransaction;
struct bilingual_str;
namespace common {
enum class PSBTError;
} // namespace common
namespace node {
enum class TransactionError;
} // namespace node
namespace wallet {
struct CreatedTransactionResult;
class CCoinControl;
class CWallet;
enum class AddressPurpose;
struct CRecipient;
struct WalletContext;
} // namespace wallet

namespace interfaces {

class Handler;
struct WalletAddress;
struct WalletBalances;
struct WalletTx;
struct WalletTxOut;
struct WalletTxStatus;
struct WalletMigrationResult;

using WalletOrderForm = std::vector<std::pair<std::string, std::string>>;
using WalletValueMap = std::map<std::string, std::string>;

//! Interface for accessing a wallet.
class Wallet
{
public:
    virtual ~Wallet() = default;

    //! Encrypt wallet.
    virtual bool encryptWallet(const SecureString& wallet_passphrase) = 0;

    //! Return whether wallet is encrypted.
    virtual bool isCrypted() = 0;

    //! Lock wallet.
    virtual bool lock() = 0;

    //! Unlock wallet.
    virtual bool unlock(const SecureString& wallet_passphrase) = 0;

    //! Return whether wallet is locked.
    virtual bool isLocked() = 0;

    //! Change wallet passphrase.
    virtual bool changeWalletPassphrase(const SecureString& old_wallet_passphrase,
        const SecureString& new_wallet_passphrase) = 0;

    //! Abort a rescan.
    virtual void abortRescan() = 0;

    //! Back up wallet.
    virtual bool backupWallet(const std::string& filename) = 0;

    //! Get wallet name.
    virtual std::string getWalletName() = 0;

    //! Pricoin: get this wallet's reusable stealth address (base58check
    //! encoding, version byte 0x53). Generated lazily and persisted to
    //! wallets/<name>/pricoin_stealth.dat. Returns empty on failure.
    virtual std::string getStealthAddress() = 0;

    //! Pricoin: build, sign and broadcast a v4 confidential transaction
    //! sending `amount` PRIC from a transparent wallet input to the given
    //! stealth address, paying a transparent `fee`. Returns the txid on
    //! success or an error string. Equivalent to the `walletsendct` RPC.
    virtual util::Result<uint256> sendConfidential(
        const std::string& dest_stealth_address,
        CAmount amount,
        CAmount fee) = 0;

    //! Pricoin: scan the chain for confidential outputs paid to this
    //! wallet's stealth identity (via rangeproof rewind). Returns the total
    //! recovered value across unspent outputs. Equivalent to
    //! `pricoin_listownct.total_recovered`.
    virtual CAmount confidentialBalance() = 0;

    // ────── Phase-6 orderbook (Tier 1) wallet interface ──────
    //
    // Read-friendly snapshot of an Order record for the GUI table.
    // String fields use the same enum spellings as the JSON-RPC layer
    // ("local"/"imported", "buy_pric"/"sell_pric", "btc"/"ltc",
    // "active"/"matched"/"filled"/"cancelled"/"expired"). Decimal
    // amounts stay in sats (int64).
    struct PricoinOfferSnapshot {
        std::string order_id;
        std::string origin;
        std::string side;
        std::string foreign_chain;
        int64_t     max_pric_amount_sat{0};
        int64_t     foreign_amount_at_max_sat{0};
        int64_t     expiry_unix_sec{0};
        std::string maker_pubkey_hex;
        std::string status;
        int64_t     pric_remaining_sat{0};
        int64_t     pric_in_flight_sat{0};
        std::string matched_with_order_id;  // empty if none
        std::string notes;
        int64_t     created_time{0};
        int64_t     updated_time{0};
    };

    struct PricoinOfferCreateParams {
        std::string side;          // "buy_pric" | "sell_pric"
        std::string foreign_chain; // "btc" | "ltc"
        int64_t     max_pric_amount_sat{0};
        int64_t     foreign_amount_at_max_sat{0};
        int64_t     expiry_unix_sec{0};
        std::string notes;
    };

    struct PricoinOfferCreateResult {
        bool        ok{false};
        std::string error;        // populated when !ok
        PricoinOfferSnapshot record{};
        std::string uri;          // canonical pricoffer:v1/<base64>
    };

    struct PricoinMatchCandidate {
        std::string their_order_id;
        int64_t     their_max_pric_sat{0};
        int64_t     their_foreign_at_max_sat{0};
        int64_t     max_actual_pric_sat{0};
        int64_t     price_advantage_milli{0};
    };

    //! Pricoin: create a local order. Generates fresh order_id, signs
    //! payload with wallet's swap-identity priv, returns record + URI.
    virtual PricoinOfferCreateResult offerCreate(const PricoinOfferCreateParams& p) = 0;

    //! Pricoin: import an offer URI from a counterparty. Verifies sig,
    //! rejects duplicates / expired / malformed.
    virtual util::Result<PricoinOfferSnapshot> offerImport(const std::string& uri) = 0;

    //! Pricoin: list all orders (Local + Imported).
    virtual std::vector<PricoinOfferSnapshot> offerList() = 0;

    //! Pricoin: read one order by id.
    virtual std::optional<PricoinOfferSnapshot> offerGet(const std::string& order_id) = 0;

    //! Pricoin: re-export the URI for a Local order. Returns empty for
    //! imported orders.
    virtual std::string offerExportUri(const std::string& order_id) = 0;

    //! Pricoin: operator-cancel an order (Active or Matched → Cancelled).
    virtual util::Result<PricoinOfferSnapshot> offerCancel(const std::string& order_id) = 0;

    //! Pricoin: lock my order to their order at the chosen actual_pric_amount.
    //! Both transition to Matched. See `pricoin_offer_match` RPC docs.
    virtual util::Result<std::pair<PricoinOfferSnapshot, PricoinOfferSnapshot>>
        offerMatch(const std::string& my_order_id,
                   const std::string& their_order_id,
                   int64_t actual_pric_amount_sat) = 0;

    //! Pricoin: mark a Matched order Filled (cascades to peer).
    virtual util::Result<PricoinOfferSnapshot> offerFill(const std::string& order_id) = 0;

    //! Pricoin: release a Matched order back to Active (cascades to peer).
    virtual util::Result<PricoinOfferSnapshot> offerUnmatch(const std::string& order_id) = 0;

    //! Pricoin: find imported offers that price-cross with my order,
    //! sorted best-first.
    virtual std::vector<PricoinMatchCandidate> offerFindMatches(const std::string& my_order_id) = 0;

    //! Pricoin: 32-byte BIP340 x-only form of the wallet's swap-identity
    //! pubkey, hex. Used as the `pubkey` field of Nostr events that
    //! announce orders this wallet maintains. Empty on locked wallet.
    virtual std::string getSwapIdentityXOnlyHex() = 0;

    //! Pricoin: produce a 64-byte BIP340 Schnorr signature over `hash`
    //! using the wallet's swap-identity priv. Returns hex on success
    //! or an error string. Used to sign Nostr `id` digests.
    virtual util::Result<std::string> signNostrEvent(const uint256& event_id_hash) = 0;

    // Get a new address.
    virtual util::Result<CTxDestination> getNewDestination(OutputType type, const std::string& label) = 0;

    //! Get public key.
    virtual bool getPubKey(const CScript& script, const CKeyID& address, CPubKey& pub_key) = 0;

    //! Sign message
    virtual SigningResult signMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) = 0;

    //! Return whether wallet has private key.
    virtual bool isSpendable(const CTxDestination& dest) = 0;

    //! Add or update address.
    virtual bool setAddressBook(const CTxDestination& dest, const std::string& name, const std::optional<wallet::AddressPurpose>& purpose) = 0;

    // Remove address.
    virtual bool delAddressBook(const CTxDestination& dest) = 0;

    //! Look up address in wallet, return whether exists.
    virtual bool getAddress(const CTxDestination& dest,
        std::string* name,
        wallet::AddressPurpose* purpose) = 0;

    //! Get wallet address list.
    virtual std::vector<WalletAddress> getAddresses() = 0;

    //! Get receive requests.
    virtual std::vector<std::string> getAddressReceiveRequests() = 0;

    //! Save or remove receive request.
    virtual bool setAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& value) = 0;

    //! Display address on external signer
    virtual util::Result<void> displayAddress(const CTxDestination& dest) = 0;

    //! Lock coin.
    virtual bool lockCoin(const COutPoint& output, bool write_to_db) = 0;

    //! Unlock coin.
    virtual bool unlockCoin(const COutPoint& output) = 0;

    //! Return whether coin is locked.
    virtual bool isLockedCoin(const COutPoint& output) = 0;

    //! List locked coins.
    virtual void listLockedCoins(std::vector<COutPoint>& outputs) = 0;

    //! Create transaction.
    virtual util::Result<wallet::CreatedTransactionResult> createTransaction(const std::vector<wallet::CRecipient>& recipients,
        const wallet::CCoinControl& coin_control,
        bool sign,
        std::optional<unsigned int> change_pos) = 0;

    //! Commit transaction.
    virtual void commitTransaction(CTransactionRef tx,
        WalletValueMap value_map,
        WalletOrderForm order_form) = 0;

    //! Return whether transaction can be abandoned.
    virtual bool transactionCanBeAbandoned(const Txid& txid) = 0;

    //! Abandon transaction.
    virtual bool abandonTransaction(const Txid& txid) = 0;

    //! Return whether transaction can be bumped.
    virtual bool transactionCanBeBumped(const Txid& txid) = 0;

    //! Create bump transaction.
    virtual bool createBumpTransaction(const Txid& txid,
        const wallet::CCoinControl& coin_control,
        std::vector<bilingual_str>& errors,
        CAmount& old_fee,
        CAmount& new_fee,
        CMutableTransaction& mtx) = 0;

    //! Sign bump transaction.
    virtual bool signBumpTransaction(CMutableTransaction& mtx) = 0;

    //! Commit bump transaction.
    virtual bool commitBumpTransaction(const Txid& txid,
        CMutableTransaction&& mtx,
        std::vector<bilingual_str>& errors,
        Txid& bumped_txid) = 0;

    //! Get a transaction.
    virtual CTransactionRef getTx(const Txid& txid) = 0;

    //! Get transaction information.
    virtual WalletTx getWalletTx(const Txid& txid) = 0;

    //! Get list of all wallet transactions.
    virtual std::set<WalletTx> getWalletTxs() = 0;

    //! Try to get updated status for a particular transaction, if possible without blocking.
    virtual bool tryGetTxStatus(const Txid& txid,
        WalletTxStatus& tx_status,
        int& num_blocks,
        int64_t& block_time) = 0;

    //! Get transaction details.
    virtual WalletTx getWalletTxDetails(const Txid& txid,
        WalletTxStatus& tx_status,
        WalletOrderForm& order_form,
        bool& in_mempool,
        int& num_blocks) = 0;

    //! Fill PSBT.
    virtual std::optional<common::PSBTError> fillPSBT(std::optional<int> sighash_type,
        bool sign,
        bool bip32derivs,
        size_t* n_signed,
        PartiallySignedTransaction& psbtx,
        bool& complete) = 0;

    //! Get balances.
    virtual WalletBalances getBalances() = 0;

    //! Get balances if possible without blocking.
    virtual bool tryGetBalances(WalletBalances& balances, uint256& block_hash) = 0;

    //! Get balance.
    virtual CAmount getBalance() = 0;

    //! Get available balance.
    virtual CAmount getAvailableBalance(const wallet::CCoinControl& coin_control) = 0;

    //! Return whether transaction input belongs to wallet.
    virtual bool txinIsMine(const CTxIn& txin) = 0;

    //! Return whether transaction output belongs to wallet.
    virtual bool txoutIsMine(const CTxOut& txout) = 0;

    //! Return debit amount if transaction input belongs to wallet.
    virtual CAmount getDebit(const CTxIn& txin) = 0;

    //! Return credit amount if transaction input belongs to wallet.
    virtual CAmount getCredit(const CTxOut& txout) = 0;

    //! Return AvailableCoins + LockedCoins grouped by wallet address.
    //! (put change in one group with wallet address)
    using CoinsList = std::map<CTxDestination, std::vector<std::tuple<COutPoint, WalletTxOut>>>;
    virtual CoinsList listCoins() = 0;

    //! Return wallet transaction output information.
    virtual std::vector<WalletTxOut> getCoins(const std::vector<COutPoint>& outputs) = 0;

    //! Get required fee.
    virtual CAmount getRequiredFee(unsigned int tx_bytes) = 0;

    //! Get minimum fee.
    virtual CAmount getMinimumFee(unsigned int tx_bytes,
        const wallet::CCoinControl& coin_control,
        int* returned_target,
        FeeReason* reason) = 0;

    //! Get tx confirm target.
    virtual unsigned int getConfirmTarget() = 0;

    // Return whether HD enabled.
    virtual bool hdEnabled() = 0;

    // Return whether the wallet is blank.
    virtual bool canGetAddresses() = 0;

    // Return whether private keys enabled.
    virtual bool privateKeysDisabled() = 0;

    // Return whether the wallet contains a Taproot scriptPubKeyMan
    virtual bool taprootEnabled() = 0;

    // Return whether wallet uses an external signer.
    virtual bool hasExternalSigner() = 0;

    // Get default address type.
    virtual OutputType getDefaultAddressType() = 0;

    //! Get max tx fee.
    virtual CAmount getDefaultMaxTxFee() = 0;

    // Remove wallet.
    virtual void remove() = 0;

    //! Register handler for unload message.
    using UnloadFn = std::function<void()>;
    virtual std::unique_ptr<Handler> handleUnload(UnloadFn fn) = 0;

    //! Register handler for show progress messages.
    using ShowProgressFn = std::function<void(const std::string& title, int progress)>;
    virtual std::unique_ptr<Handler> handleShowProgress(ShowProgressFn fn) = 0;

    //! Register handler for status changed messages.
    using StatusChangedFn = std::function<void()>;
    virtual std::unique_ptr<Handler> handleStatusChanged(StatusChangedFn fn) = 0;

    //! Register handler for address book changed messages.
    using AddressBookChangedFn = std::function<void(const CTxDestination& address,
        const std::string& label,
        bool is_mine,
        wallet::AddressPurpose purpose,
        ChangeType status)>;
    virtual std::unique_ptr<Handler> handleAddressBookChanged(AddressBookChangedFn fn) = 0;

    //! Register handler for transaction changed messages.
    using TransactionChangedFn = std::function<void(const Txid& txid, ChangeType status)>;
    virtual std::unique_ptr<Handler> handleTransactionChanged(TransactionChangedFn fn) = 0;

    //! Register handler for keypool changed messages.
    using CanGetAddressesChangedFn = std::function<void()>;
    virtual std::unique_ptr<Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn fn) = 0;

    //! Return pointer to internal wallet class, useful for testing.
    virtual wallet::CWallet* wallet() { return nullptr; }
};

//! Wallet chain client that in addition to having chain client methods for
//! starting up, shutting down, and registering RPCs, also has additional
//! methods (called by the GUI) to load and create wallets.
class WalletLoader : public ChainClient
{
public:
    //! Create new wallet.
    virtual util::Result<std::unique_ptr<Wallet>> createWallet(const std::string& name, const SecureString& passphrase, uint64_t wallet_creation_flags, std::vector<bilingual_str>& warnings) = 0;

    //! Load existing wallet.
    virtual util::Result<std::unique_ptr<Wallet>> loadWallet(const std::string& name, std::vector<bilingual_str>& warnings) = 0;

    //! Return default wallet directory.
    virtual std::string getWalletDir() = 0;

    //! Restore backup wallet
    virtual util::Result<std::unique_ptr<Wallet>> restoreWallet(const fs::path& backup_file, const std::string& wallet_name, std::vector<bilingual_str>& warnings, bool load_after_restore) = 0;

    //! Migrate a wallet
    virtual util::Result<WalletMigrationResult> migrateWallet(const std::string& name, const SecureString& passphrase) = 0;

    //! Returns true if wallet stores encryption keys
    virtual bool isEncrypted(const std::string& wallet_name) = 0;

    //! Return available wallets in wallet directory.
    virtual std::vector<std::pair<std::string, std::string>> listWalletDir() = 0;

    //! Return interfaces for accessing wallets (if any).
    virtual std::vector<std::unique_ptr<Wallet>> getWallets() = 0;

    //! Register handler for load wallet messages. This callback is triggered by
    //! createWallet and loadWallet above, and also triggered when wallets are
    //! loaded at startup or by RPC.
    using LoadWalletFn = std::function<void(std::unique_ptr<Wallet> wallet)>;
    virtual std::unique_ptr<Handler> handleLoadWallet(LoadWalletFn fn) = 0;

    //! Return pointer to internal context, useful for testing.
    virtual wallet::WalletContext* context() { return nullptr; }
};

//! Information about one wallet address.
struct WalletAddress
{
    CTxDestination dest;
    bool is_mine;
    wallet::AddressPurpose purpose;
    std::string name;

    WalletAddress(CTxDestination dest, bool is_mine, wallet::AddressPurpose purpose, std::string name)
        : dest(std::move(dest)), is_mine(is_mine), purpose(std::move(purpose)), name(std::move(name))
    {
    }
};

//! Collection of wallet balances.
struct WalletBalances
{
    CAmount balance = 0;
    CAmount unconfirmed_balance = 0;
    CAmount immature_balance = 0;
    CAmount used_balance = 0;
    CAmount nonmempool_balance = 0;
    CAmount confidential_balance = 0;   // Pricoin: sum of recovered v4 CT outputs

    bool balanceChanged(const WalletBalances& prev) const
    {
        return balance != prev.balance || unconfirmed_balance != prev.unconfirmed_balance ||
               immature_balance != prev.immature_balance ||
               used_balance != prev.used_balance || nonmempool_balance != prev.nonmempool_balance ||
               confidential_balance != prev.confidential_balance;
    }
};

// Wallet transaction information.
struct WalletTx
{
    CTransactionRef tx;
    std::vector<bool> txin_is_mine;
    std::vector<bool> txout_is_mine;
    std::vector<bool> txout_is_change;
    std::vector<CTxDestination> txout_address;
    std::vector<bool> txout_address_is_mine;
    CAmount credit;
    CAmount debit;
    CAmount change;
    int64_t time;
    std::map<std::string, std::string> value_map;
    bool is_coinbase;

    bool operator<(const WalletTx& a) const { return tx->GetHash() < a.tx->GetHash(); }
};

//! Updated transaction status.
struct WalletTxStatus
{
    int block_height;
    int blocks_to_maturity;
    int depth_in_main_chain;
    unsigned int time_received;
    uint32_t lock_time;
    bool is_trusted;
    bool is_abandoned;
    bool is_coinbase;
    bool is_in_main_chain;
};

//! Wallet transaction output.
struct WalletTxOut
{
    CTxOut txout;
    int64_t time;
    int depth_in_main_chain = -1;
    bool is_spent = false;
};

//! Migrated wallet info
struct WalletMigrationResult
{
    std::unique_ptr<Wallet> wallet;
    std::optional<std::string> watchonly_wallet_name;
    std::optional<std::string> solvables_wallet_name;
    fs::path backup_path;
};

//! Return implementation of Wallet interface. This function is defined in
//! dummywallet.cpp and throws if the wallet component is not compiled.
std::unique_ptr<Wallet> MakeWallet(wallet::WalletContext& context, const std::shared_ptr<wallet::CWallet>& wallet);

//! Return implementation of ChainClient interface for a wallet loader. This
//! function will be undefined in builds where ENABLE_WALLET is false.
std::unique_ptr<WalletLoader> MakeWalletLoader(Chain& chain, ArgsManager& args);

} // namespace interfaces

#endif // BITCOIN_INTERFACES_WALLET_H
