/**
 * The MIT License (MIT) THIS TOOL IS ONLY FOR EDUCATIONAL PURPOSES ONLY
    Copyright (C) 2022 Anonymous Hacks Date: Thus june 2, 2022

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software
    and associated documentation files (the "Software"), to deal in the Software without restriction
    , including without limitation the rights to use, copy, modify, merge, publish, distribute, 
    sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is 
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies
    or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
    INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
    PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef SSHCRED_HPP_
#define SSHCRED_HPP_

#include <libssh/libssh.h>

#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>
#include <fstream>

#define SSHCRED_VERSION "0.0.3"


class SSHCred {

    public:
        SSHCred () {
            auto_open_shell = 1;
            port = 22;
        }
        void setPassworddb(std::string);
        void setPort(int port);
        void setHost(std::string target_host);
        void setUserdb(std::string userdb);
        void setUsername(std::string username);
        void setStopOnSuccess(int flag);
        void printPubkey();
        void printBanner();
        void printAuthenticationMethods();
        void brute();

    private:
        std::string target_host;
        std::string passworddb;
        std::string userdb;
        std::string username;
        int port;
        int auto_open_shell;
        int flag;
        ssh_session getNewSession();

};

void print_version();
void print_help();

// std::string whi = "\033[1;37m",
// red = "\033[1;31m",
// blu = "\033[1;34m",
// res = "\e[0m";

#endif /* SSHCRED_HPP_*/