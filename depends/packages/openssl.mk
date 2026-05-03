package=openssl
$(package)_version=3.0.16
$(package)_download_path=https://www.openssl.org/source
$(package)_file_name=openssl-$($(package)_version).tar.gz
$(package)_sha256_hash=57e03c50feab5d31b152af2b764f10379aecd8ee92f16c985983ce4a99f7ef86

# Pricoin: re-introduce OpenSSL into depends for Qt6's TLS plugin.
# Bitcoin Core dropped OpenSSL years ago because it had no use for it,
# but Qt6's QSslSocket needs *some* TLS backend — the depends Qt build
# was previously configured with -no-openssl, which left the TLS
# plugins disabled and made wss:// (Nostr orderbook + DM transport)
# silently fail at runtime with "SSL Sockets are not supported on this
# platform." Linking openssl as a static depends package + flipping
# Qt to -openssl-linked produces a Qt that ships the OpenSSL TLS
# backend plugin (libqopensslbackend) in its tls/ plugin directory,
# which we already allow-list in macdeployqtplus.
#
# We pin openssl 3.0.16 (LTS, supported until 2026-09) — long-lived
# enough not to require frequent depends rebuilds, recent enough that
# old TLS 1.0/1.1 cruft is gone.

define $(package)_set_vars
# Configure target per host_os. OpenSSL's Configure has its own
# triplet vocabulary distinct from autotools.
# `no-asm` disables OpenSSL's inline x86_64/aarch64 assembly. Slight
# crypto-perf hit but avoids GCC inline-asm incompatibilities with
# the depends hardening flags (-fcf-protection=full, etc.). Qt's
# TLS plugin is not in any hot path for us — the BN math runs once
# per WebSocket handshake, not per byte — so the perf hit is fine.
$(package)_config_opts := no-asm no-shared no-tests no-dso no-engine
# Static lib only (we link directly into the Qt plugin).
$(package)_config_opts += --prefix=$(host_prefix) --libdir=lib --openssldir=$(host_prefix)/etc/ssl
# Trim attack surface: drop hardware-accel asm we don't need,
# disable features Qt's TLS plugin doesn't use.
$(package)_config_opts += no-zlib no-comp no-ssl3 no-ssl3-method
$(package)_config_opts += no-weak-ssl-ciphers
# Reproducible build hooks.
$(package)_config_env := AR="$$($(package)_ar)"
$(package)_config_env += CC="$$($(package)_cc)"
$(package)_config_env += CFLAGS="$$($(package)_cflags) $$($(package)_cppflags)"
$(package)_config_env += LDFLAGS="$$($(package)_ldflags)"
$(package)_config_env += RANLIB="$$($(package)_ranlib)"

# Per-host Configure triplet.
$(package)_config_opts_linux := linux-x86_64
$(package)_config_opts_mingw32 := mingw64
$(package)_config_opts_darwin := darwin64-arm64-cc
endef

define $(package)_config_cmds
  ./Configure $($(package)_config_opts)
endef

define $(package)_build_cmds
  $(MAKE) build_libs
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install_dev
endef

define $(package)_postprocess_cmds
  rm -rf bin share doc man
endef
