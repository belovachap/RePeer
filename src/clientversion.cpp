#include <clientversion.h>
#include <util/translation.h>

#include <tinyformat.h>

#include <sstream>
#include <string>
#include <vector>

using namespace std;

string format_full_version(int major, int minor, string codename)
{
    std::ostringstream ss;
    ss << major << "." << minor << " " << codename;
    return ss.str();
}

string FormatFullVersion()
{
    return format_full_version(REPEER_VERSION_MAJOR, REPEER_VERSION_MINOR, "Grimpoteuthis");
}

/**
 * See BIP 14 spec (https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki)
 */
string format_useragent(int major, int minor)
{
    std::ostringstream ss;
    ss << "/RePeer:" << major << "." << minor << "/";
    return ss.str();
}

string FormatUseragent()
{
    return format_useragent(REPEER_VERSION_MAJOR, REPEER_VERSION_MINOR);
}
