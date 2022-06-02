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
#ifndef SHELL_HPP_
#define SHELL_HPP_

#include <libssh/libssh.h>

#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>


class Shell {
    public:
        Shell(std::string host, std::string username, int port) {

            this->host = host;
            this->port = port;
            this->username = username;

            if (port == 0)
                port = 22;
            
            ssh = getNewSession();
        }

        ~Shell() {
            ssh_free(ssh);
        }
        void authServer();
        int authUser();
        int interactiveShellSession();
        void setSession(ssh_session ssh);
        ssh_session getSSH();


    private:
        ssh_session ssh;
        std::string host;
        std::string username;
        int port;
        int authUserPubkey();
        int authUserPassword();
        int authUserKbdInt();
        int authUserNone();
        ssh_session getNewSession();
}; 

#endif /*SHELL_HPP_*/