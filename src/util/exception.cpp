// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/exception.h>

#include <logging.h>
#include <tinyformat.h>

#include <exception>
#include <iostream>
#include <string>
#include <typeinfo>

static std::string FormatException(const std::exception* pex, std::string_view thread_name)
{
    const char* pszModule = "bitcoin";
    if (pex)
        return strprintf(
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, thread_name);
    else
        return strprintf(
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, thread_name);
}

void PrintExceptionContinue(const std::exception* pex, std::string_view thread_name)
{
    std::string message = FormatException(pex, thread_name);
    LogPrintf("\n\n************************\n%s\n", message);
    tfm::format(std::cerr, "\n\n************************\n%s\n", message);
}
