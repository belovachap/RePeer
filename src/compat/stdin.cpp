// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat/stdin.h>

#include <cstdio>

#include <termios.h>
#include <unistd.h>
#include <poll.h>

// https://stackoverflow.com/questions/1413445/reading-a-password-from-stdcin
void SetStdinEcho(bool enable)
{
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

bool StdinTerminal()
{
    return isatty(fileno(stdin));
}

bool StdinReady()
{
    if (!StdinTerminal()) {
        return true;
    }
    struct pollfd fds;
    fds.fd = STDIN_FILENO;
    fds.events = POLLIN;
    return poll(&fds, 1, 0) == 1;
}

NoechoInst::NoechoInst() { SetStdinEcho(false); }
NoechoInst::~NoechoInst() { SetStdinEcho(true); }
