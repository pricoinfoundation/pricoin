// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <swap/esplora_backend.h>

#include <support/events.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

namespace pricoin::swap {

namespace {

// ─────────────────────────────────────────────────────────────────
// Minimal libevent-based HTTP client. Mirrors the pattern in
// bitcoin-cli.cpp (synchronous request via a fresh event_base, with
// HTTPReply collected through a callback). Plain HTTP only; HTTPS
// is a follow-up commit.
// ─────────────────────────────────────────────────────────────────

struct HTTPReply {
    int status{0};
    int error{-1};
    std::string body;
};

void http_request_done(struct evhttp_request* req, void* ctx)
{
    auto* reply = static_cast<HTTPReply*>(ctx);
    if (req == nullptr) {
        reply->status = 0;
        return;
    }
    reply->status = evhttp_request_get_response_code(req);
    if (auto* buf = evhttp_request_get_input_buffer(req)) {
        const size_t size = evbuffer_get_length(buf);
        const char* data = reinterpret_cast<const char*>(evbuffer_pullup(buf, size));
        if (data) reply->body.assign(data, size);
        evbuffer_drain(buf, size);
    }
}

void http_error_cb(enum evhttp_request_error err, void* ctx)
{
    auto* reply = static_cast<HTTPReply*>(ctx);
    reply->error = err;
}

std::string http_errorstring(int code)
{
    switch (code) {
        case EVREQ_HTTP_TIMEOUT:        return "timeout";
        case EVREQ_HTTP_EOF:            return "eof";
        case EVREQ_HTTP_INVALID_HEADER: return "invalid header";
        case EVREQ_HTTP_BUFFER_ERROR:   return "buffer error";
        case EVREQ_HTTP_REQUEST_CANCEL: return "canceled";
        case EVREQ_HTTP_DATA_TOO_LONG:  return "data too long";
        default:                        return "unknown";
    }
}

// Parse "http://host[:port][/prefix]" into (host, port, path_prefix).
// Throws std::invalid_argument if the URL isn't http://.
struct ParsedURL {
    std::string host;
    uint16_t port{80};
    std::string path_prefix; // "" or "/api" etc.; empty or starts with '/'
};

ParsedURL ParseHttpURL(const std::string& url)
{
    static const std::string kPrefix = "http://";
    if (url.compare(0, kPrefix.size(), kPrefix) != 0) {
        throw std::invalid_argument("EsploraBackend URL must start with http:// — HTTPS support deferred");
    }
    std::string rest = url.substr(kPrefix.size());

    ParsedURL out;
    auto slash = rest.find('/');
    std::string host_port;
    if (slash == std::string::npos) {
        host_port = rest;
    } else {
        host_port = rest.substr(0, slash);
        out.path_prefix = rest.substr(slash);
        // Strip trailing slashes for clean concat.
        while (!out.path_prefix.empty() && out.path_prefix.back() == '/') {
            out.path_prefix.pop_back();
        }
    }

    auto colon = host_port.rfind(':');
    if (colon == std::string::npos) {
        out.host = host_port;
    } else {
        out.host = host_port.substr(0, colon);
        const std::string port_str = host_port.substr(colon + 1);
        const auto p = ToIntegral<uint16_t>(port_str);
        if (!p || *p == 0) {
            throw std::invalid_argument(strprintf("Invalid port in URL: %s", url));
        }
        out.port = *p;
    }
    if (out.host.empty()) {
        throw std::invalid_argument(strprintf("Empty host in URL: %s", url));
    }
    return out;
}

// One-shot HTTP request. Method is EVHTTP_REQ_GET / EVHTTP_REQ_POST.
// `path` should start with '/' and be relative to the URL prefix
// (the prefix is prepended internally).
HTTPReply DoRequest(
    const ParsedURL& url,
    int timeout_seconds,
    int method,
    const std::string& path,
    const std::string* body_for_post = nullptr,
    const char* content_type = "text/plain")
{
    raii_event_base base = obtain_event_base();
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(
        base.get(), url.host, url.port);
    if (!evcon) {
        throw ChainBackendError(
            strprintf("evhttp_connection_base_new failed for %s:%u", url.host, url.port));
    }
    evhttp_connection_set_timeout(evcon.get(),
        timeout_seconds > 0 ? timeout_seconds : 30);

    HTTPReply reply;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, &reply);
    if (!req) {
        throw ChainBackendError("evhttp_request_new failed");
    }
    evhttp_request_set_error_cb(req.get(), http_error_cb);

    auto* hdrs = evhttp_request_get_output_headers(req.get());
    evhttp_add_header(hdrs, "Host", url.host.c_str());
    evhttp_add_header(hdrs, "Connection", "close");
    evhttp_add_header(hdrs, "User-Agent", "Pricoin/swap/esplora");

    if (body_for_post) {
        evhttp_add_header(hdrs, "Content-Type", content_type);
        auto* out = evhttp_request_get_output_buffer(req.get());
        evbuffer_add(out, body_for_post->data(), body_for_post->size());
    }

    const std::string full_path = url.path_prefix + path;
    int rc = evhttp_make_request(evcon.get(), req.release(),
        static_cast<evhttp_cmd_type>(method), full_path.c_str());
    if (rc != 0) {
        throw ChainBackendError("evhttp_make_request failed");
    }
    event_base_dispatch(base.get());

    if (reply.status == 0) {
        const std::string err_str = (reply.error >= 0)
            ? http_errorstring(reply.error)
            : "no response";
        throw ChainBackendError(strprintf("HTTP error talking to %s:%u%s — %s",
            url.host, url.port, full_path, err_str));
    }
    return reply;
}

// Helpers — strip surrounding whitespace from a body the server may
// have padded with newlines. Esplora's plain-text endpoints (height,
// tx hex, broadcast txid) sometimes have a trailing \n.
std::string Trim(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\n' || s[a] == '\r' || s[a] == '\t')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\n' || s[b - 1] == '\r' || s[b - 1] == '\t')) --b;
    return s.substr(a, b - a);
}

// Ensure 200 ≤ status < 300; throw with a helpful message otherwise.
void Require2xx(const HTTPReply& reply, const std::string& path)
{
    if (reply.status < 200 || reply.status >= 300) {
        throw ChainBackendError(strprintf("Esplora %s returned HTTP %d: %s",
            path, reply.status, reply.body));
    }
}

UniValue ParseJSON(const std::string& body, const std::string& context)
{
    UniValue v;
    if (!v.read(body)) {
        throw ChainBackendError(strprintf("Esplora %s returned invalid JSON: %s",
            context, body.substr(0, 200)));
    }
    return v;
}

// ─────────────────────────────────────────────────────────────────
// EsploraBackend implementation.
// ─────────────────────────────────────────────────────────────────

class EsploraBackend final : public ChainBackend {
public:
    EsploraBackend(EsploraBackendOptions opts, ParsedURL parsed)
        : m_opts(std::move(opts)), m_url(std::move(parsed)) {}

    std::string Name() const override { return m_opts.chain_name; }

    int GetTipHeight() override
    {
        const std::string path = "/blocks/tip/height";
        auto reply = DoRequest(m_url, m_opts.timeout_seconds, EVHTTP_REQ_GET, path);
        Require2xx(reply, path);
        const std::string trimmed = Trim(reply.body);
        const auto h = ToIntegral<int>(trimmed);
        if (!h) {
            throw ChainBackendError(strprintf(
                "Esplora %s returned non-integer body: %s", path, reply.body));
        }
        return *h;
    }

    std::string GetTxHex(const std::string& txid) override
    {
        ValidateTxid(txid);
        const std::string path = "/tx/" + txid + "/hex";
        auto reply = DoRequest(m_url, m_opts.timeout_seconds, EVHTTP_REQ_GET, path);
        Require2xx(reply, path);
        return Trim(reply.body);
    }

    TxStatus GetTxStatus(const std::string& txid) override
    {
        ValidateTxid(txid);
        const std::string path = "/tx/" + txid + "/status";
        auto reply = DoRequest(m_url, m_opts.timeout_seconds, EVHTTP_REQ_GET, path);
        Require2xx(reply, path);
        const UniValue v = ParseJSON(reply.body, path);
        if (!v.isObject()) {
            throw ChainBackendError(strprintf(
                "Esplora %s expected JSON object", path));
        }
        TxStatus out;
        if (const auto& confirmed_field = v.find_value("confirmed"); confirmed_field.isBool()) {
            out.confirmed = confirmed_field.get_bool();
        }
        if (out.confirmed) {
            if (const auto& h = v.find_value("block_height"); h.isNum()) {
                out.block_height = h.getInt<int>();
            }
            if (const auto& bh = v.find_value("block_hash"); bh.isStr()) {
                out.block_hash = bh.get_str();
            }
            if (const auto& bt = v.find_value("block_time"); bt.isNum()) {
                out.block_time = bt.getInt<int64_t>();
            }
        }
        return out;
    }

    std::vector<AddressTx> GetAddressTxs(const std::string& address) override
    {
        ValidateAddress(address);
        const std::string path = "/address/" + address + "/txs";
        auto reply = DoRequest(m_url, m_opts.timeout_seconds, EVHTTP_REQ_GET, path);
        Require2xx(reply, path);
        const UniValue v = ParseJSON(reply.body, path);
        if (!v.isArray()) {
            throw ChainBackendError(strprintf(
                "Esplora %s expected JSON array", path));
        }
        std::vector<AddressTx> out;
        out.reserve(v.size());
        for (size_t i = 0; i < v.size(); ++i) {
            const UniValue& tx = v[i];
            if (!tx.isObject()) continue;
            AddressTx atx;
            if (const auto& tid = tx.find_value("txid"); tid.isStr()) {
                atx.txid = tid.get_str();
            } else {
                continue; // can't surface a tx without an id
            }
            // Parse status sub-object.
            if (const auto& st = tx.find_value("status"); st.isObject()) {
                if (const auto& c = st.find_value("confirmed"); c.isBool()) {
                    atx.status.confirmed = c.get_bool();
                }
                if (atx.status.confirmed) {
                    if (const auto& h = st.find_value("block_height"); h.isNum()) {
                        atx.status.block_height = h.getInt<int>();
                    }
                    if (const auto& bh = st.find_value("block_hash"); bh.isStr()) {
                        atx.status.block_hash = bh.get_str();
                    }
                    if (const auto& bt = st.find_value("block_time"); bt.isNum()) {
                        atx.status.block_time = bt.getInt<int64_t>();
                    }
                }
            }
            // Sum value-paid-to-this-address across vouts. Esplora
            // gives each vout's scriptpubkey_address; we match by
            // string against the queried address.
            int64_t value_in = 0;
            if (const auto& vout = tx.find_value("vout"); vout.isArray()) {
                for (size_t k = 0; k < vout.size(); ++k) {
                    const UniValue& o = vout[k];
                    if (!o.isObject()) continue;
                    const auto& addr = o.find_value("scriptpubkey_address");
                    if (!addr.isStr() || addr.get_str() != address) continue;
                    if (const auto& val = o.find_value("value"); val.isNum()) {
                        value_in += val.getInt<int64_t>();
                    }
                }
            }
            atx.value_received_sat = value_in;
            out.push_back(std::move(atx));
        }
        return out;
    }

    std::vector<AddressUtxo> GetAddressUtxos(const std::string& address) override
    {
        ValidateAddress(address);
        const std::string path = "/address/" + address + "/utxo";
        auto reply = DoRequest(m_url, m_opts.timeout_seconds, EVHTTP_REQ_GET, path);
        Require2xx(reply, path);
        const UniValue v = ParseJSON(reply.body, path);
        if (!v.isArray()) {
            throw ChainBackendError(strprintf(
                "Esplora %s expected JSON array", path));
        }
        std::vector<AddressUtxo> out;
        out.reserve(v.size());
        for (size_t i = 0; i < v.size(); ++i) {
            const UniValue& u = v[i];
            if (!u.isObject()) continue;
            AddressUtxo aux;
            if (const auto& tid = u.find_value("txid"); tid.isStr()) {
                aux.txid = tid.get_str();
            } else continue;
            if (const auto& vo = u.find_value("vout"); vo.isNum()) {
                aux.vout = vo.getInt<int32_t>();
            }
            if (const auto& val = u.find_value("value"); val.isNum()) {
                aux.value_sat = val.getInt<int64_t>();
            }
            if (const auto& st = u.find_value("status"); st.isObject()) {
                if (const auto& c = st.find_value("confirmed"); c.isBool()) {
                    aux.status.confirmed = c.get_bool();
                }
                if (aux.status.confirmed) {
                    if (const auto& h = st.find_value("block_height"); h.isNum()) {
                        aux.status.block_height = h.getInt<int>();
                    }
                    if (const auto& bh = st.find_value("block_hash"); bh.isStr()) {
                        aux.status.block_hash = bh.get_str();
                    }
                    if (const auto& bt = st.find_value("block_time"); bt.isNum()) {
                        aux.status.block_time = bt.getInt<int64_t>();
                    }
                }
            }
            out.push_back(std::move(aux));
        }
        return out;
    }

    AddressBalance GetAddressBalance(const std::string& address) override
    {
        ValidateAddress(address);
        const std::string path = "/address/" + address;
        auto reply = DoRequest(m_url, m_opts.timeout_seconds, EVHTTP_REQ_GET, path);
        Require2xx(reply, path);
        const UniValue v = ParseJSON(reply.body, path);
        AddressBalance out;
        // Esplora returns: chain_stats (confirmed) + mempool_stats (unconfirmed).
        // Each is { funded_txo_count, funded_txo_sum, spent_txo_count, spent_txo_sum, tx_count }.
        auto extract = [&](const UniValue& stats) -> int64_t {
            if (!stats.isObject()) return 0;
            int64_t funded = 0, spent = 0;
            if (const auto& f = stats.find_value("funded_txo_sum"); f.isNum()) funded = f.getInt<int64_t>();
            if (const auto& s = stats.find_value("spent_txo_sum");  s.isNum()) spent  = s.getInt<int64_t>();
            return funded - spent;
        };
        if (const auto& cs = v.find_value("chain_stats"); cs.isObject()) {
            out.confirmed_sat = extract(cs);
            if (const auto& fc = cs.find_value("funded_txo_count"); fc.isNum()) {
                out.utxo_count = fc.getInt<int>();
                if (const auto& sc = cs.find_value("spent_txo_count"); sc.isNum()) {
                    out.utxo_count -= sc.getInt<int>();
                }
            }
        }
        if (const auto& ms = v.find_value("mempool_stats"); ms.isObject()) {
            out.unconfirmed_sat = extract(ms);
        }
        return out;
    }

    std::string Broadcast(const std::string& tx_hex) override
    {
        if (tx_hex.empty() || tx_hex.size() % 2 != 0) {
            throw ChainBackendError("tx_hex empty or not byte-aligned");
        }
        for (char c : tx_hex) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                throw ChainBackendError("tx_hex contains non-hex characters");
            }
        }
        const std::string path = "/tx";
        auto reply = DoRequest(m_url, m_opts.timeout_seconds, EVHTTP_REQ_POST,
            path, &tx_hex, "text/plain");
        Require2xx(reply, path);
        return Trim(reply.body);
    }

private:
    void ValidateTxid(const std::string& txid)
    {
        if (txid.size() != 64) {
            throw ChainBackendError(strprintf("txid must be 64 hex characters, got %zu", txid.size()));
        }
        for (char c : txid) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                throw ChainBackendError("txid contains non-hex characters");
            }
        }
    }
    void ValidateAddress(const std::string& addr)
    {
        // Esplora is permissive — base58, bech32, etc. We only sanity-
        // check that the address has no path-control characters that
        // would let a caller forge the URL.
        for (char c : addr) {
            if (c == '/' || c == '?' || c == '#' || c == '&' || c < 0x20 || c >= 0x7F) {
                throw ChainBackendError("address contains illegal characters for URL path");
            }
        }
        if (addr.empty() || addr.size() > 100) {
            throw ChainBackendError("address has implausible length");
        }
    }

    EsploraBackendOptions m_opts;
    ParsedURL m_url;
};

} // namespace

std::shared_ptr<ChainBackend> MakeEsploraBackend(const EsploraBackendOptions& opts)
{
    if (opts.chain_name.empty()) {
        throw std::invalid_argument("EsploraBackend chain_name is required");
    }
    ParsedURL parsed = ParseHttpURL(opts.base_url); // throws on HTTPS / malformed
    return std::make_shared<EsploraBackend>(opts, std::move(parsed));
}

} // namespace pricoin::swap
