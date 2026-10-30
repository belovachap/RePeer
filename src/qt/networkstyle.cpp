// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/networkstyle.h>

#include <qt/guiconstants.h>

#include <chainparamsbase.h>
#include <tinyformat.h>

#include <QApplication>

static const struct {
    const char *networkId;
    const char *appName;
} network_styles[] = {
    {"main", QAPP_APP_NAME_DEFAULT},
    {"test", QAPP_APP_NAME_TESTNET},
    {"signet", QAPP_APP_NAME_SIGNET},
    {"regtest", QAPP_APP_NAME_REGTEST},
};

// titleAddText needs to be const char* for tr()
NetworkStyle::NetworkStyle(const QString &_appName, const char *_titleAddText):
    appName(_appName),
    titleAddText(qApp->translate("SplashScreen", _titleAddText))
{

}

const NetworkStyle* NetworkStyle::instantiate(const std::string& networkId)
{
    std::string titleAddText = networkId == CBaseChainParams::MAIN ? "" : strprintf("[%s]", networkId);
    for (const auto& network_style : network_styles) {
        if (networkId == network_style.networkId) {
            return new NetworkStyle(
                    network_style.appName,
                    titleAddText.c_str());
        }
    }
    return nullptr;
}
