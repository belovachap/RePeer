// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CLIENTVERSION_H
#define BITCOIN_CLIENTVERSION_H

#include <util/macros.h>

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif //HAVE_CONFIG_H

// Check that required client information is defined
#if !defined(REPEER_VERSION_MAJOR) || !defined(REPEER_VERSION_MINOR) || !defined(REPEER_VERSION_REVISION)
#error Client version information missing: version is not defined by bitcoin-config.h or in any other way
#endif

//! Copyright string used in Windows .rc files
#define COPYRIGHT_STR "2009-" STRINGIZE(COPYRIGHT_YEAR) " " COPYRIGHT_HOLDERS_FINAL

/**
 * bitcoind-res.rc includes this file, but it cannot cope with real c++ code.
 * WINDRES_PREPROC is defined to indicate that its pre-processor is running.
 * Anything other than a define should be guarded below.
 */

#if !defined(WINDRES_PREPROC)

#include <string>

using namespace std;

// This is used in the database wrapper for some reason...
static const int CLIENT_VERSION =
                             10000 * CLIENT_VERSION_MAJOR
                         +     100 * CLIENT_VERSION_MINOR
                         +       1 * CLIENT_VERSION_BUILD;

string format_full_version(int major, int minor, int revision, string codename);
string FormatFullVersion();
string format_useragent(int major, int minor, int revision);
string FormatUseragent();

string CopyrightHolders(const std::string& strPrefix);

/** Returns licensing information (for -version) */
string LicenseInfo();

#endif // WINDRES_PREPROC

#endif // BITCOIN_CLIENTVERSION_H
