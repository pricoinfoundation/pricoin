# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Wallet functionality used by bitcoind and bitcoin-wallet executables.
add_library(bitcoin_wallet STATIC EXCLUDE_FROM_ALL
  coincontrol.cpp
  coinselection.cpp
  context.cpp
  crypter.cpp
  db.cpp
  dump.cpp
  external_signer_scriptpubkeyman.cpp
  feebumper.cpp
  fees.cpp
  interfaces.cpp
  load.cpp
  migrate.cpp
  pricoin_adaptor_swap.cpp
  pricoin_btc_holding.cpp
  pricoin_btc_musig2_nonce_records.cpp
  pricoin_chain_watcher.cpp
  pricoin_clsag_nonce_records.cpp
  pricoin_offer.cpp
  pricoin_stealth.cpp
  pricoin_swap_ceremony.cpp
  pricoin_swap_refund.cpp
  pricoin_swap_session.cpp
  receive.cpp
  rpc/addresses.cpp
  rpc/backup.cpp
  rpc/coins.cpp
  rpc/encrypt.cpp
  rpc/pricoin_ct.cpp
  rpc/signmessage.cpp
  rpc/spend.cpp
  rpc/transactions.cpp
  rpc/util.cpp
  rpc/wallet.cpp
  scriptpubkeyman.cpp
  spend.cpp
  sqlite.cpp
  transaction.cpp
  wallet.cpp
  walletdb.cpp
  walletutil.cpp
)
target_link_libraries(bitcoin_wallet
  PRIVATE
    core_interface
    bitcoin_common
    SQLite3::SQLite3
    univalue
    Boost::headers
    secp256k1
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
)
