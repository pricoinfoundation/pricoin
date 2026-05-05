// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_holding_page.h>

#include <interfaces/node.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>
#include <tinyformat.h>

#include <univalue.h>

#include <cmath>

#include <QApplication>
#include <QClipboard>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFontMetrics>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

#include <optional>
#include <string>

namespace {

// Local helper, mirrors PricoinSwapsPage's CallWalletRpc.
std::optional<UniValue> CallWalletRpc(WalletModel* wm,
                                       const std::string& method,
                                       const UniValue& params,
                                       std::string* err)
{
    if (!wm) { if (err) *err = "wallet not attached"; return std::nullopt; }
    const QString wallet_name = wm->getWalletName();
    std::string uri;
    if (!wallet_name.isEmpty()) {
        QByteArray enc = QUrl::toPercentEncoding(wallet_name);
        uri = "/wallet/" + std::string(enc.constData(), enc.length());
    }
    try {
        return wm->node().executeRpc(method, params, uri);
    } catch (const UniValue& e) {
        if (err) {
            if (e.isObject() && e.exists("message")) *err = e["message"].get_str();
            else                                     *err = e.write();
        }
    } catch (const std::exception& e) {
        if (err) *err = e.what();
    } catch (...) {
        if (err) *err = "unknown RPC error";
    }
    return std::nullopt;
}

// 8-decimal sat → "X.XXXXXXXX" rendering. Uses int64 division so we
// don't lose precision the way naive double division would.
QString FormatSat(int64_t sat)
{
    const bool neg = sat < 0;
    const int64_t v = neg ? -sat : sat;
    const int64_t whole = v / 100'000'000;
    const int64_t frac  = v % 100'000'000;
    return (neg ? QStringLiteral("-") : QString())
        + QString::number(whole)
        + QStringLiteral(".")
        + QString::asprintf("%08lld", static_cast<long long>(frac));
}

} // namespace

PricoinHoldingPage::PricoinHoldingPage(const PlatformStyle* platformStyle, QWidget* parent)
    : QWidget(parent),
      m_platform_style(platformStyle)
{
    buildLayout();
}

PricoinHoldingPage::~PricoinHoldingPage()
{
    // Same shutdown-race defense as PricoinSwapsPage — stop the timer
    // explicitly so a tick can't fire after the model is torn down.
    if (m_refresh_timer) {
        m_refresh_timer->stop();
        m_refresh_timer->disconnect();
    }
}

void PricoinHoldingPage::buildLayout()
{
    auto* outer = new QVBoxLayout(this);

    // Top row: status + refresh.
    auto* top = new QHBoxLayout();
    m_btn_refresh = new QPushButton(tr("Refresh now"), this);
    top->addWidget(m_btn_refresh);
    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    top->addWidget(m_status, /*stretch=*/1);
    outer->addLayout(top);

    auto build_panel = [this](const QString& chain_label,
                                ChainPanel& panel) -> QGroupBox* {
        auto* box = new QGroupBox(chain_label, this);
        box->setStyleSheet(QStringLiteral("QGroupBox { font-weight: bold; }"));
        auto* form = new QFormLayout(box);

        panel.address = new QLineEdit(box);
        panel.address->setReadOnly(true);
        panel.address->setPlaceholderText(tr("(loading…)"));
        // Bech32 BTC/LTC addresses are up to ~62 chars (P2WSH = 62,
        // P2TR/P2WPKH ≈ 42-62). Compute a minimum width from the
        // current font so the full address is visible without
        // horizontal scrolling.
        {
            QFontMetrics fm(panel.address->font());
            const int char_w = fm.horizontalAdvance(QLatin1Char('M'));
            panel.address->setMinimumWidth(char_w * 70);
        }
        auto* addr_row = new QHBoxLayout();
        addr_row->addWidget(panel.address, /*stretch=*/1);
        panel.btn_copy = new QPushButton(tr("Copy"), box);
        addr_row->addWidget(panel.btn_copy);
        form->addRow(tr("Address:"), addr_row);

        panel.balance = new QLabel(tr("(loading…)"), box);
        QFont bf = panel.balance->font();
        bf.setBold(true);
        panel.balance->setFont(bf);
        form->addRow(tr("Balance:"), panel.balance);

        panel.hint = new QLabel(box);
        panel.hint->setStyleSheet(QStringLiteral("QLabel { color: #555; }"));
        panel.hint->setWordWrap(true);
        form->addRow(QString(), panel.hint);

        auto* btn_row = new QHBoxLayout();
        panel.btn_sweep = new QPushButton(tr("Sweep all to…"), box);
        btn_row->addWidget(panel.btn_sweep);
        btn_row->addStretch();
        form->addRow(QString(), btn_row);
        return box;
    };

    outer->addWidget(build_panel(QStringLiteral("BTC"), m_btc));
    outer->addWidget(build_panel(QStringLiteral("LTC"), m_ltc));
    outer->addStretch();

    connect(m_btn_refresh,    &QPushButton::clicked, this, &PricoinHoldingPage::onRefreshClicked);
    connect(m_btc.btn_copy,   &QPushButton::clicked, this, &PricoinHoldingPage::onCopyBtcClicked);
    connect(m_ltc.btn_copy,   &QPushButton::clicked, this, &PricoinHoldingPage::onCopyLtcClicked);
    connect(m_btc.btn_sweep,  &QPushButton::clicked, this, &PricoinHoldingPage::onSweepBtcClicked);
    connect(m_ltc.btn_sweep,  &QPushButton::clicked, this, &PricoinHoldingPage::onSweepLtcClicked);

    m_refresh_timer = new QTimer(this);
    m_refresh_timer->setInterval(15000);   // 15 s
    connect(m_refresh_timer, &QTimer::timeout, this, &PricoinHoldingPage::onAutoRefreshTick);
}

void PricoinHoldingPage::setModel(WalletModel* model)
{
    m_model = model;
    if (m_model) {
        connect(m_model, &QObject::destroyed, this, [this]() {
            m_model = nullptr;
            if (m_refresh_timer) m_refresh_timer->stop();
        });
        if (m_refresh_timer && !m_refresh_timer->isActive()) m_refresh_timer->start();
        onRefreshClicked();
    } else {
        if (m_refresh_timer) m_refresh_timer->stop();
    }
}

void PricoinHoldingPage::setStatus(const QString& msg, bool error)
{
    m_status->setStyleSheet(error
        ? QStringLiteral("QLabel { color: #b71c1c; }")
        : QStringLiteral("QLabel { color: #1b5e20; }"));
    m_status->setText(msg);
}

void PricoinHoldingPage::refreshChain(const QString& chain, ChainPanel& panel)
{
    if (!m_model) return;

    // Address — derived locally; doesn't depend on the chain backend
    // being reachable, so always populates.
    {
        UniValue p{UniValue::VARR};
        p.push_back(chain.toStdString());
        std::string err;
        auto r = CallWalletRpc(m_model, "pricoin_btc_getaddress", p, &err);
        if (r) {
            panel.address->setText(QString::fromStdString((*r)["address"].get_str()));
        } else {
            panel.address->setText(QString());
            panel.address->setPlaceholderText(tr("(error: %1)")
                .arg(QString::fromStdString(err)));
        }
    }

    // Balance — requires the chain backend (Esplora) to be configured
    // and reachable. Surface the error inline rather than failing.
    {
        UniValue p{UniValue::VARR};
        p.push_back(chain.toStdString());
        std::string err;
        auto r = CallWalletRpc(m_model, "pricoin_btc_getbalance", p, &err);
        if (r) {
            const int64_t conf   = (*r)["confirmed_sat"].getInt<int64_t>();
            const int64_t unconf = (*r)["unconfirmed_sat"].getInt<int64_t>();
            const int     n      = (*r)["utxo_count"].getInt<int>();
            panel.balance->setText(tr("%1 %2").arg(FormatSat(conf), chain.toUpper()));
            QString hint = tr("%1 UTXO%2").arg(n).arg(n == 1 ? QString() : QStringLiteral("s"));
            if (unconf != 0) {
                hint += tr(" — %1 %2 unconfirmed")
                    .arg(FormatSat(unconf), chain.toUpper());
            }
            panel.hint->setText(hint);
        } else {
            panel.balance->setText(tr("(unavailable)"));
            panel.hint->setText(tr(
                "Chain backend not reachable. Configure %1watchurl in pricoin.conf "
                "(e.g. %1watchurl=https://blockstream.info/api), or %1watchurl="
                "<your self-hosted Esplora>. Error: %2")
                .arg(chain).arg(QString::fromStdString(err)));
        }
    }
}

void PricoinHoldingPage::onRefreshClicked()
{
    if (!m_model) return;
    refreshChain(QStringLiteral("btc"), m_btc);
    refreshChain(QStringLiteral("ltc"), m_ltc);
}

void PricoinHoldingPage::onAutoRefreshTick()
{
    if (!m_model) return;
    onRefreshClicked();
}

void PricoinHoldingPage::onCopyBtcClicked()
{
    if (m_btc.address && !m_btc.address->text().isEmpty()) {
        QApplication::clipboard()->setText(m_btc.address->text());
        setStatus(tr("BTC address copied to clipboard."));
    }
}

void PricoinHoldingPage::onCopyLtcClicked()
{
    if (m_ltc.address && !m_ltc.address->text().isEmpty()) {
        QApplication::clipboard()->setText(m_ltc.address->text());
        setStatus(tr("LTC address copied to clipboard."));
    }
}

void PricoinHoldingPage::doSweep(const QString& chain, const ChainPanel& panel)
{
    if (!m_model) return;

    // Pull a current sat/vB fee estimate + UTXO count from the chain
    // backend so we can pre-populate the fee field with something
    // reasonable instead of the old 1000-sat hardcode (which was
    // wildly off in either direction depending on the fee market).
    //
    //   estimated_size_vb = N_inputs * input_size + 1 * output_size + overhead
    //   estimated_fee_sat = ceil(size * sat_per_vb)
    //
    // Per-input sizes are vbyte counts for a key-path-spend of the
    // holding wallet's address type (P2TR for BTC, P2WPKH for LTC).
    int64_t suggested_fee = 1000;       // fallback if backend unreachable
    QString fee_hint;
    {
        UniValue pe{UniValue::VARR};
        pe.push_back(chain.toStdString());
        std::string err_e;
        auto e = CallWalletRpc(m_model, "pricoin_chainwatch_fee_estimates",
                                pe, &err_e);
        UniValue pb{UniValue::VARR};
        pb.push_back(chain.toStdString());
        std::string err_b;
        auto b = CallWalletRpc(m_model, "pricoin_btc_getbalance", pb, &err_b);

        const int input_vb  = (chain == "btc") ? 58 : 68;  // P2TR / P2WPKH
        const int output_vb = (chain == "btc") ? 43 : 31;
        const int overhead_vb = 11;
        // Cover a wide range of realistic UTXO counts. If we can read
        // the backend's count, use it; otherwise assume 3 inputs.
        int n_inputs = 3;
        if (b) {
            const auto utxo_count = (*b)["utxo_count"];
            if (utxo_count.isNum() && utxo_count.getInt<int>() > 0) {
                n_inputs = utxo_count.getInt<int>();
            }
        }
        const int est_size_vb = n_inputs * input_vb + output_vb + overhead_vb;

        // Pick the 6-block target if available, else any nearby target.
        double sat_per_vb = -1.0;
        if (e && e->isObject()) {
            for (int t : {6, 10, 3, 20, 144, 2, 1}) {
                const auto v = (*e)[strprintf("%d", t)];
                if (v.isNum() && v.get_real() > 0) {
                    sat_per_vb = v.get_real();
                    break;
                }
            }
        }
        if (sat_per_vb > 0.0) {
            suggested_fee = static_cast<int64_t>(
                std::ceil(static_cast<double>(est_size_vb) * sat_per_vb));
            fee_hint = tr("Suggested: %1 sat/vB × ~%2 vB tx (%3 input%4) = %5 sats")
                .arg(QString::number(sat_per_vb, 'f', 1))
                .arg(est_size_vb)
                .arg(n_inputs)
                .arg(n_inputs == 1 ? QString() : QStringLiteral("s"))
                .arg(suggested_fee);
        } else {
            fee_hint = tr("(fee-rate unavailable — using fallback default)");
        }
    }

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Sweep %1 holding wallet").arg(chain.toUpper()));
    auto* form = new QFormLayout(&dlg);
    form->addRow(new QLabel(tr("Sweeps every UTXO at the holding-wallet "
                                "address into a single tx paying the "
                                "destination below. The fee is taken from "
                                "the swept total."), &dlg));
    auto* dest = new QLineEdit(&dlg);
    dest->setPlaceholderText(chain == "btc"
        ? tr("bc1q… bech32 / bc1p… bech32m address")
        : tr("ltc1q… bech32 address"));
    form->addRow(tr("Destination:"), dest);
    auto* fee = new QLineEdit(&dlg);
    fee->setText(QString::number(suggested_fee));
    form->addRow(tr("Fee (sats):"), fee);
    auto* fee_hint_label = new QLabel(fee_hint, &dlg);
    fee_hint_label->setStyleSheet(QStringLiteral("QLabel { color: #555; }"));
    fee_hint_label->setWordWrap(true);
    form->addRow(QString(), fee_hint_label);
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    QObject::connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    form->addRow(bb);
    if (dlg.exec() != QDialog::Accepted) return;

    const QString dest_text = dest->text().trimmed();
    bool fee_ok = false;
    const int64_t fee_sat = fee->text().toLongLong(&fee_ok);
    if (dest_text.isEmpty()) {
        setStatus(tr("Destination address required."), true);
        return;
    }
    if (!fee_ok || fee_sat < 0) {
        setStatus(tr("Fee must be a non-negative integer (sats)."), true);
        return;
    }

    UniValue p{UniValue::VARR};
    p.push_back(chain.toStdString());
    p.push_back(dest_text.toStdString());
    p.push_back(fee_sat);
    std::string err;
    auto r = CallWalletRpc(m_model, "pricoin_btc_sweep", p, &err);
    if (!r) {
        setStatus(tr("Sweep failed: %1").arg(QString::fromStdString(err)), true);
        return;
    }
    const QString txid = QString::fromStdString((*r)["txid"].get_str());
    setStatus(tr("%1 sweep broadcast — txid %2…")
        .arg(chain.toUpper()).arg(txid.left(16)));
    refreshChain(chain, const_cast<ChainPanel&>(panel));
}

void PricoinHoldingPage::onSweepBtcClicked() { doSweep(QStringLiteral("btc"), m_btc); }
void PricoinHoldingPage::onSweepLtcClicked() { doSweep(QStringLiteral("ltc"), m_ltc); }
