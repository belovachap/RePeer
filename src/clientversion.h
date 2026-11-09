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

// This is used in the database wrapper for some reason...
static const int CLIENT_VERSION = 0;

string format_full_version(int major, int minor, string codename);
string FormatFullVersion();
string format_useragent(int major, int minor);
string FormatUseragent();

#endif // CLIENTVERSION_H
