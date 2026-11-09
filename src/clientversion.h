#ifndef CLIENTVERSION_H
#define CLIENTVERSION_H

#include <string>

#include <config/bitcoin-config.h>
#include <util/macros.h>

using namespace std;

// Check that required client information is defined
#if !defined(REPEER_VERSION_MAJOR) || !defined(REPEER_VERSION_MINOR)
#error Client version information missing: version is not defined by bitcoin-config.h or in any other way
#endif

//! Copyright string used in Windows .rc files
#define COPYRIGHT_STR "2009-" STRINGIZE(COPYRIGHT_YEAR) " " COPYRIGHT_HOLDERS_FINAL

// This is used in the database wrapper for some reason...
static const int CLIENT_VERSION = 0;

string format_full_version(int major, int minor, int revision, string codename);
string FormatFullVersion();
string format_useragent(int major, int minor, int revision);
string FormatUseragent();

string CopyrightHolders(const string& strPrefix);

/** Returns licensing information (for -version) */
string LicenseInfo();

#endif // CLIENTVERSION_H
