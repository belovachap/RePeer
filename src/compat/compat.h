// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPAT_COMPAT_H
#define BITCOIN_COMPAT_COMPAT_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <unistd.h>

// We map Linux / BSD error functions and codes, to the equivalent
// Windows definitions, and use the WSA* names throughout our code.
// Note that glibc defines EWOULDBLOCK as EAGAIN (see errno.h).
typedef unsigned int SOCKET;
#include <cerrno>
#define WSAGetLastError()   errno
#define WSAEINVAL           EINVAL
#define WSAEWOULDBLOCK      EWOULDBLOCK
#define WSAEAGAIN           EAGAIN
#define WSAEMSGSIZE         EMSGSIZE
#define WSAEINTR            EINTR
#define WSAEINPROGRESS      EINPROGRESS
#define WSAEADDRINUSE       EADDRINUSE
#define INVALID_SOCKET      (SOCKET)(~0)
#define SOCKET_ERROR        -1

// Windows defines MAX_PATH as it's maximum path length.
// We define MAX_PATH for use on non-Windows systems.
#define MAX_PATH            1024

// ssize_t is POSIX, and not present when using MSVC.
#ifdef _MSC_VER
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

// The type of the option value passed to getsockopt & setsockopt
// differs between Windows and non-Windows.
typedef void* sockopt_arg_type;

#define MAIN_FUNCTION int main(int argc, char* argv[])

// Note these both should work with the current usage of poll, but best to be safe
// WIN32 poll is broken https://daniel.haxx.se/blog/2012/10/10/wsapoll-is-broken/
// __APPLE__ poll is broke https://github.com/bitcoin/bitcoin/pull/14336#issuecomment-437384408
#if defined(__linux__)
#define USE_POLL
#endif

// MSG_NOSIGNAL is not available on some platforms, if it doesn't exist define it as 0
#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

// MSG_DONTWAIT is not available on some platforms, if it doesn't exist define it as 0
#if !defined(MSG_DONTWAIT)
#define MSG_DONTWAIT 0
#endif

#endif // BITCOIN_COMPAT_COMPAT_H
