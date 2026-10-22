#include <clientversion.h>
#include <util/translation.h>

#include <tinyformat.h>

#include <sstream>
#include <string>
#include <vector>

using namespace std;

string format_full_version(int major, int minor, int revision, string codename)
{
    std::ostringstream ss;
    ss << major << "." << minor << "." << revision << " " << codename;
    return ss.str();
}

string FormatFullVersion()
{
    return format_full_version(REPEER_VERSION_MAJOR, REPEER_VERSION_MINOR, REPEER_VERSION_REVISION, "Grimpoteuthis");
}

/**
 * See BIP 14 spec (https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki)
 */
string format_useragent(int major, int minor, int revision)
{
    std::ostringstream ss;
    ss << "/RePeer:" << major << "." << minor << "." << revision << "/";
    return ss.str();
}

string FormatUseragent()
{
    return format_useragent(REPEER_VERSION_MAJOR, REPEER_VERSION_MINOR, REPEER_VERSION_REVISION);
}

std::string CopyrightHolders(const std::string& strPrefix)
{
    const auto copyright_devs = strprintf(_(COPYRIGHT_HOLDERS).translated, COPYRIGHT_HOLDERS_SUBSTITUTION);
    std::string strCopyrightHolders = strPrefix + copyright_devs;

    // Make sure Bitcoin Core copyright is not removed by accident
    if (copyright_devs.find("Bitcoin Core") == std::string::npos) {
        // Set correct start year for Bitcoin
        std::string strPrefixBitcoin = strPrefix;
        size_t pos = strPrefixBitcoin.find("2011");
        if (pos != std::string::npos) {
            strPrefixBitcoin.replace(pos, 4, "2009");
        }
        strCopyrightHolders += "\n" + strPrefixBitcoin + "The Bitcoin Core developers";
    }
    return strCopyrightHolders;
}

std::string LicenseInfo()
{
    const std::string URL_SOURCE_CODE = "<https://github.com/peercoin/peercoin>";

    return CopyrightHolders(strprintf(_("Copyright (C) %i-%i").translated, 2011, COPYRIGHT_YEAR) + " ") + "\n" +
           "\n" +
           strprintf(_("Please contribute if you find %s useful. "
                       "Visit %s for further information about the software.").translated, PACKAGE_NAME, "<" PACKAGE_URL ">") +
           "\n" +
           strprintf(_("The source code is available from %s.").translated, URL_SOURCE_CODE) +
           "\n" +
           "\n" +
           _("This is experimental software.").translated + "\n" +
           strprintf(_("Distributed under the MIT software license, see the accompanying file %s or %s").translated, "COPYING", "<https://opensource.org/licenses/MIT>") +
           "\n";
}
