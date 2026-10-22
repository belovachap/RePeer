#include <boost/test/unit_test.hpp>

#include "clientversion.h"

BOOST_AUTO_TEST_SUITE(clientversion_tests)

BOOST_AUTO_TEST_CASE(format_full_version_test)
{
    BOOST_CHECK_EQUAL(format_full_version(13, 0, 1, "Grimpoteuthis"), "13.0.1 Grimpoteuthis");
}

BOOST_AUTO_TEST_CASE(format_useragent_test)
{
    BOOST_CHECK_EQUAL(format_useragent(13, 0, 1), "/RePeer:13.0.1/");
}

BOOST_AUTO_TEST_SUITE_END()
