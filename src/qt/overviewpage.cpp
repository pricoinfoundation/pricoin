// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/overviewpage.h>
#include <qt/forms/ui_overviewpage.h>

#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/transactionfilterproxy.h>
#include <qt/transactionoverviewwidget.h>
#include <qt/transactiontablemodel.h>
#include <qt/walletmodel.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <univalue.h>

#include <QAbstractItemDelegate>
#include <QAbstractItemView>
#include <QApplication>
#include <QDateTime>
#include <QFormLayout>
#include <QFrame>
#include <QHeaderView>
#include <QLabel>
#include <QPainter>
#include <QStatusTipEvent>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QUrl>
#include <QVBoxLayout>

#include <algorithm>
#include <map>

#define DECORATION_SIZE 54
#define NUM_ITEMS 5

Q_DECLARE_METATYPE(interfaces::WalletBalances)

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    explicit TxViewDelegate(const PlatformStyle* _platformStyle, QObject* parent = nullptr)
        : QAbstractItemDelegate(parent), platformStyle(_platformStyle)
    {
        connect(this, &TxViewDelegate::width_changed, this, &TxViewDelegate::sizeHintChanged);
    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const override
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
        icon = platformStyle->SingleColorIcon(icon);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if(value.canConvert<QBrush>())
        {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        painter->setPen(foreground);
        QRect boundingRect;
        painter->drawText(addressRect, Qt::AlignLeft | Qt::AlignVCenter, address, &boundingRect);

        if(amount < 0)
        {
            foreground = COLOR_NEGATIVE;
        }
        else if(!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = option.palette.color(QPalette::Text);
        }
        painter->setPen(foreground);
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::SeparatorStyle::ALWAYS);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }

        QRect amount_bounding_rect;
        painter->drawText(amountRect, Qt::AlignRight | Qt::AlignVCenter, amountText, &amount_bounding_rect);

        painter->setPen(option.palette.color(QPalette::Text));
        QRect date_bounding_rect;
        painter->drawText(amountRect, Qt::AlignLeft | Qt::AlignVCenter, GUIUtil::dateTimeStr(date), &date_bounding_rect);

        // 0.4*date_bounding_rect.width() is used to visually distinguish a date from an amount.
        const int minimum_width = 1.4 * date_bounding_rect.width() + amount_bounding_rect.width();
        const auto search = m_minimum_width.find(index.row());
        if (search == m_minimum_width.end() || search->second != minimum_width) {
            m_minimum_width[index.row()] = minimum_width;
            Q_EMIT width_changed(index);
        }

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        const auto search = m_minimum_width.find(index.row());
        const int minimum_text_width = search == m_minimum_width.end() ? 0 : search->second;
        return {DECORATION_SIZE + 8 + minimum_text_width, DECORATION_SIZE};
    }

    BitcoinUnit unit{BitcoinUnit::BTC};

Q_SIGNALS:
    //! An intermediate signal for emitting from the `paint() const` member function.
    void width_changed(const QModelIndex& index) const;

private:
    const PlatformStyle* platformStyle;
    mutable std::map<int, int> m_minimum_width;
};

#include <qt/overviewpage.moc>

OverviewPage::OverviewPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    m_platform_style{platformStyle},
    txdelegate(new TxViewDelegate(platformStyle, this))
{
    ui->setupUi(this);

    // use a SingleColorIcon for the "out of sync warning" icon
    QIcon icon = m_platform_style->SingleColorIcon(QStringLiteral(":/icons/warning"));
    ui->labelTransactionsStatus->setIcon(icon);
    ui->labelWalletStatus->setIcon(icon);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, &TransactionOverviewWidget::clicked, this, &OverviewPage::handleTransactionClicked);

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
    connect(ui->labelWalletStatus, &QPushButton::clicked, this, &OverviewPage::outOfSyncWarningClicked);
    connect(ui->labelTransactionsStatus, &QPushButton::clicked, this, &OverviewPage::outOfSyncWarningClicked);

    // Pricoin Phase B: surface the recovered confidential balance below the
    // existing transparent balance block. The CT balance comes from rangeproof
    // rewind on every chain output paid to this wallet's stealth identity, so
    // it's a separate quantity from `WalletBalances::balance` (which only sees
    // transparent UTXOs). We refresh it on the same trigger as transparent
    // balance updates.
    if (auto* main = layout()) {
        auto* ct_frame = new QFrame(this);
        ct_frame->setFrameShape(QFrame::StyledPanel);
        auto* form = new QFormLayout(ct_frame);
        m_pricoin_ct_label = new QLabel("--", ct_frame);
        m_pricoin_ct_label->setStyleSheet("QLabel { font-weight: bold; }");
        auto* title = new QLabel(tr("Confidential balance:"), ct_frame);
        form->addRow(title, m_pricoin_ct_label);
        auto* note = new QLabel(tr(
            "Sum of values recovered from confidential outputs paid to your "
            "stealth address. Updates whenever the transparent balance does."), ct_frame);
        note->setWordWrap(true);
        note->setStyleSheet("QLabel { color: #666; font-size: 11px; }");
        form->addRow(note);

        // Persistent confidential-transaction history table. Unlike the
        // balance (a snapshot quantity), this lists individual received +
        // sent CT movements and SURVIVES spending, via the
        // `pricoin_listcttransactions` RPC.
        auto* tx_title = new QLabel(tr("Confidential transactions:"), ct_frame);
        form->addRow(tx_title);
        m_pricoin_ct_tx_table = new QTableWidget(0, 5, ct_frame);
        m_pricoin_ct_tx_table->setHorizontalHeaderLabels(
            {tr("Type"), tr("Amount"), tr("Height"), tr("Status"), tr("TxID")});
        m_pricoin_ct_tx_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_pricoin_ct_tx_table->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_pricoin_ct_tx_table->setSelectionMode(QAbstractItemView::SingleSelection);
        m_pricoin_ct_tx_table->verticalHeader()->setVisible(false);
        m_pricoin_ct_tx_table->horizontalHeader()->setStretchLastSection(true);
        m_pricoin_ct_tx_table->setMinimumHeight(160);
        form->addRow(m_pricoin_ct_tx_table);

        // Insert just below the existing balance block (top of overview).
        if (auto* vlay = qobject_cast<QVBoxLayout*>(main)) {
            vlay->insertWidget(1, ct_frame);
        } else {
            main->addWidget(ct_frame);
        }
    }
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        Q_EMIT transactionClicked(filter->mapToSource(index));
}

void OverviewPage::setPrivacy(bool privacy)
{
    m_privacy = privacy;
    clientModel->getOptionsModel()->setOption(OptionsModel::OptionID::MaskValues, privacy);
    const auto& balances = walletModel->getCachedBalance();
    if (balances.balance != -1) {
        setBalance(balances);
    }

    ui->listTransactions->setVisible(!m_privacy);

    const QString status_tip = m_privacy ? tr("Privacy mode activated for the Overview tab. To unmask the values, uncheck Settings->Mask values.") : "";
    setStatusTip(status_tip);
    QStatusTipEvent event(status_tip);
    QApplication::sendEvent(this, &event);
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::setBalance(const interfaces::WalletBalances& balances)
{
    BitcoinUnit unit = walletModel->getOptionsModel()->getDisplayUnit();
    ui->labelBalance->setText(BitcoinUnits::formatWithPrivacy(unit, balances.balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithPrivacy(unit, balances.unconfirmed_balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    ui->labelImmature->setText(BitcoinUnits::formatWithPrivacy(unit, balances.immature_balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    ui->labelTotal->setText(BitcoinUnits::formatWithPrivacy(unit, balances.balance + balances.unconfirmed_balance + balances.immature_balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = balances.immature_balance != 0;

    ui->labelImmature->setVisible(showImmature);
    ui->labelImmatureText->setVisible(showImmature);

    if (m_pricoin_ct_label) {
        // Read from the snapshot so the displayed CT balance always
        // matches the transparent figures from the same poll. Calling
        // wallet().confidentialBalance() separately re-locks the wallet
        // and could race against an in-flight scan.
        m_pricoin_ct_label->setText(BitcoinUnits::formatWithPrivacy(
            unit, balances.confidential_balance,
            BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    }
    refreshPricoinCtTransactions();
}

void OverviewPage::refreshPricoinCtTransactions()
{
    if (!m_pricoin_ct_tx_table || !walletModel) return;

    // best-effort: fetch the persistent CT history. The recovery cache is
    // warm here (the CT balance for this same poll already synced it), so
    // this is cheap; on any error we just leave the table unchanged.
    UniValue result;
    try {
        UniValue params{UniValue::VARR};
        params.push_back(0);  // startheight
        const QString wname = walletModel->getWalletName();
        std::string uri;
        if (!wname.isEmpty()) {
            const QByteArray enc = QUrl::toPercentEncoding(wname);
            uri = "/wallet/" + std::string(enc.constData(), enc.length());
        }
        result = walletModel->node().executeRpc("pricoin_listcttransactions", params, uri);
    } catch (...) {
        return;
    }
    if (!result.isObject() || !result.exists("transactions")
        || !result["transactions"].isArray()) {
        return;
    }
    const UniValue& rows = result["transactions"];

    // Newest first (mempool / unknown height == -1 sorts to the top).
    std::vector<const UniValue*> sorted;
    sorted.reserve(rows.size());
    for (size_t i = 0; i < rows.size(); ++i) sorted.push_back(&rows[i]);
    auto height_of = [](const UniValue& r) {
        return r["height"].isNum() ? r["height"].getInt<int>() : -1;
    };
    std::sort(sorted.begin(), sorted.end(),
        [&](const UniValue* a, const UniValue* b) { return height_of(*a) > height_of(*b); });

    m_pricoin_ct_tx_table->setRowCount(0);
    for (const UniValue* rp : sorted) {
        const UniValue& r = *rp;
        const std::string type = r["type"].isStr() ? r["type"].get_str() : "";
        const bool is_sent = (type == "sent");
        const bool is_change = r.exists("is_change") && r["is_change"].isBool()
            && r["is_change"].get_bool();

        QString type_str = is_sent ? tr("Sent") : tr("Received");
        if (is_change) type_str += tr(" (change)");

        // amount is a STR_AMOUNT (already signed: + received, - sent).
        const QString amount = QString::fromStdString(r["amount"].getValStr());

        const int height = height_of(r);
        const QString height_str = height < 0 ? tr("mempool") : QString::number(height);

        QString status;
        if (is_sent) {
            status = tr("sent");
        } else {
            const bool spent = r.exists("spent") && r["spent"].isBool() && r["spent"].get_bool();
            status = spent ? tr("spent") : tr("unspent");
        }

        const QString txid = r["txid"].isStr()
            ? QString::fromStdString(r["txid"].get_str()) : QString{};
        QString txid_short = txid.left(16);
        if (txid.size() > 16) txid_short += QStringLiteral("…");

        const int row = m_pricoin_ct_tx_table->rowCount();
        m_pricoin_ct_tx_table->insertRow(row);
        auto set = [&](int col, const QString& text, const QString& tip = {}) {
            auto* item = new QTableWidgetItem(text);
            if (!tip.isEmpty()) item->setToolTip(tip);
            m_pricoin_ct_tx_table->setItem(row, col, item);
        };
        set(0, type_str);
        set(1, amount);
        set(2, height_str);
        set(3, status);
        set(4, txid_short, txid);
    }
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if (model) {
        // Show warning, for example if this is a prerelease version
        connect(model, &ClientModel::alertsChanged, this, &OverviewPage::updateAlerts);
        updateAlerts(model->getStatusBarWarnings());

        connect(model->getOptionsModel(), &OptionsModel::fontForMoneyChanged, this, &OverviewPage::setMonospacedFont);
        setMonospacedFont(clientModel->getOptionsModel()->getFontForMoney());
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        connect(filter.get(), &TransactionFilterProxy::rowsInserted, this, &OverviewPage::LimitTransactionRows);
        connect(filter.get(), &TransactionFilterProxy::rowsRemoved, this, &OverviewPage::LimitTransactionRows);
        connect(filter.get(), &TransactionFilterProxy::rowsMoved, this, &OverviewPage::LimitTransactionRows);
        LimitTransactionRows();
        // Keep up to date with wallet
        setBalance(model->getCachedBalance());
        connect(model, &WalletModel::balanceChanged, this, &OverviewPage::setBalance);

        connect(model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &OverviewPage::updateDisplayUnit);
    }

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void OverviewPage::changeEvent(QEvent* e)
{
    if (e->type() == QEvent::PaletteChange) {
        QIcon icon = m_platform_style->SingleColorIcon(QStringLiteral(":/icons/warning"));
        ui->labelTransactionsStatus->setIcon(icon);
        ui->labelWalletStatus->setIcon(icon);
    }

    QWidget::changeEvent(e);
}

// Only show most recent NUM_ITEMS rows
void OverviewPage::LimitTransactionRows()
{
    if (filter && ui->listTransactions && ui->listTransactions->model() && filter.get() == ui->listTransactions->model()) {
        for (int i = 0; i < filter->rowCount(); ++i) {
            ui->listTransactions->setRowHidden(i, i >= NUM_ITEMS);
        }
    }
}

void OverviewPage::updateDisplayUnit()
{
    if (walletModel && walletModel->getOptionsModel()) {
        const auto& balances = walletModel->getCachedBalance();
        if (balances.balance != -1) {
            setBalance(balances);
        }

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}

void OverviewPage::setMonospacedFont(const QFont& f)
{
    ui->labelBalance->setFont(f);
    ui->labelUnconfirmed->setFont(f);
    ui->labelImmature->setFont(f);
    ui->labelTotal->setFont(f);
}
