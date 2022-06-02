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

#include "shell.hpp"

/**
 * Function for authenticating the server
*/
void Shell::authServer() {

    ssh_key key;
    int ret;

    //Get the server public key
    // ret = ssh_get_publickey(ssh, &key);
    ret = ssh_get_server_publickey(ssh, &key);
    if(ret != SSH_OK) {
        std::cerr << "-| [~] Error getting server publickey\n";
        std::cerr << ssh_get_error(ssh) << std::endl;
    }

    unsigned char *hash;
    size_t hashlen;
    // Get the hashes
    ret = ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA1, &hash, &hashlen);

    if(ret != SSH_OK) {

        std::cout << stderr, "-| [~] Error getting server publickey hash\n";
        
    }
    /**
     * Create an enum type of ssh_known_hosts_e and use it with the
     * ssh_session_is_known_server function, to know the state of the server
    */
    enum ssh_known_hosts_e known = ssh_session_is_known_server(ssh);

    switch(known) {
        case SSH_KNOWN_HOSTS_OK: //The server is a known server
            std::cout << "-| [*] SSH Server Authentication Successful\n";
            break;
        case SSH_KNOWN_HOSTS_UNKNOWN: //The server is unknown
            std::cout << "-| [~] SSH Server Unknown.\n";
            std::cout << "-| [*] For security reason, it is recommended to quit the program now.\n";
            break;
        case SSH_KNOWN_HOSTS_NOT_FOUND: //The server is not found
            std::cout << "-| [~] SSH Server Not Found.\n";
            std::cout << "-| [*] For security reason, it is recommended to quit the program now.\n";
            break;
        case SSH_KNOWN_HOSTS_CHANGED: //The server is changed
            std::cout << "-| [~] SSH Server is changed.\n";
            ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA1, hash, hashlen);
            std::cout << "-| [~] It is now: " << hash << std::endl;
            std::cout << "-| [*] For security reason, it is recommended to quit the program now.\n";
            break;
        case SSH_KNOWN_HOSTS_OTHER: //Not found but another exists
            std::cout << "-| [~] SSH server not found but another type exists.\n";
            std::cout << "-| [*] For security reason, it is recommended to quit the program now.\n";
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            std::cout << "-| [~] Error Authenticating server\n";
            break;
        default:
            std::cout << "-| [~] Error: " << known << std::endl;
            break;
    }

    ssh_clean_pubkey_hash(&hash);
    if(known != SSH_KNOWN_HOSTS_OK &&
       known != SSH_KNOWN_HOSTS_ERROR) {
           std::cout << "-| [~] Do you want to accept and remember this host?(y/N): ";
           char ans[5];
           fgets(ans, sizeof(ans), stdin);
           if(ans[0] == 'Y' || ans[0] == 'y')
                ssh_session_update_known_hosts(ssh);
    }

}

/**
 * Function for authenticating the user
*/

int Shell::authUser() {

    int method, ret;
    ret = ssh_userauth_none(ssh, NULL);
    if(ret == SSH_AUTH_ERROR || ret == SSH_AUTH_SUCCESS)
        return ret;

    method = ssh_userauth_list(ssh, NULL);
    if(method & SSH_AUTH_METHOD_NONE) { //None method
        ret = authUserNone();
        if(ret == SSH_AUTH_SUCCESS) return ret;
    }
    if(method & SSH_AUTH_METHOD_PUBLICKEY) { //public key authentication
        ret = authUserPubkey();
        if(ret == SSH_AUTH_SUCCESS) return ret;
    }
    if(method & SSH_AUTH_METHOD_PASSWORD) { //password authentication
        ret = authUserPassword();
        if(ret == SSH_AUTH_SUCCESS) return ret;
    }
    if(method & SSH_AUTH_METHOD_INTERACTIVE) { //user keybroad authentication method
        ret = authUserKbdInt();
        if(ret == SSH_AUTH_SUCCESS) return ret;
    }

    return SSH_ERROR;
}
/**
 *  Authenticating the user using password 
*/
int Shell::authUserPassword() {

    char *password;
    password = getpass("-| [*] Enter password: ");
    int ret;
    ret = ssh_userauth_password(ssh, NULL, password);
    if(ret == SSH_AUTH_ERROR) {
        
        std::cerr << "-| [!] Authentication using password failed\n";
        std::cout << ssh_get_error(ssh);
        return -1;
    }

    return ret;
}

/**
 * Authenticating the user using public key
*/

int Shell::authUserPubkey() {

    int ret = ssh_userauth_publickey_auto(ssh, NULL, NULL);
    if(ret == SSH_AUTH_ERROR) {

        std::cerr << "-| [!] Authentication using public key failed\n"; 
        std::cerr << ssh_get_error(ssh);
        return -1;
    }

    return ret;
}

/**
 * Authenticating the user using keyboard interactive
*/
int Shell::authUserKbdInt() {
    int ret;
    ret = ssh_userauth_kbdint(ssh, NULL, NULL);
    /**
     * If the returned value is SSH_AUTH_INFO, it means the server
     * have send some challenges to the user that he/she has to answer
     * before granting access.
    */

   while(ret == SSH_AUTH_INFO) {

       const char *name, *instruction, *prompt;
       int nprompt, iprompt;

       name = ssh_userauth_kbdint_getname(ssh);
       std::cout << "- | [*] " << name << std::endl;
       instruction = ssh_userauth_kbdint_getinstruction(ssh);
       std::cout << "- | [*] " << instruction << std::endl;

       nprompt = ssh_userauth_kbdint_getnprompts(ssh);

       for(iprompt = 0; iprompt < nprompt; ++iprompt) {
           char *echo;
           prompt = ssh_userauth_kbdint_getprompt(ssh, iprompt, echo);

           if(echo) {
               char buffer[1024], *ptr;

               std::cout << prompt;
               if(fgets(buffer, sizeof(buffer), stdin) == NULL)
                    return SSH_AUTH_ERROR;
                buffer[sizeof(buffer) - 1] = '\0';
                if((ptr = strchr(buffer, '\n')) != NULL) {
                    *ptr = '\0';

                    if(ssh_userauth_kbdint_setanswer(ssh, iprompt, buffer) < 0)
                        return SSH_AUTH_ERROR;
                    memset(buffer, 0, sizeof(buffer));
                }
           }else {

               char *ptr;
               ptr = getpass(prompt);
               if(ssh_userauth_kbdint_setanswer(ssh, iprompt, ptr) < 0)
                    return SSH_AUTH_ERROR;
           }
       }

        ret = ssh_userauth_kbdint(ssh, NULL, NULL);
    
   }
   return ret;
}

/**
 * Authenticating the user using none
*/

int Shell::authUserNone() {

    int ret;
    ret = ssh_userauth_none(ssh, NULL);
    if(ret == SSH_AUTH_ERROR) {
        std::cerr << "-| [*] Authentication using none failed\n";
        std::cerr << ssh_get_error(ssh) << std::endl;
        return -1;
    }

    return ret;
}

/**
 * Function for creating a channel
 * and droping into a shell to execute commands
*/
int Shell::interactiveShellSession() {

    int ret;

    // create a channel
    ssh_channel channel = ssh_channel_new(ssh);
    if(!channel) {
        std::cerr << "-| [~] Failed to create a channel\n";
        return SSH_ERROR;
    }

    // open the channel
    ret = ssh_channel_open_session(channel);
    if(ret != SSH_OK) {
        std::cerr << "-| [~] Failed to open a channel\n";
        return SSH_ERROR;
    }

    ret = ssh_channel_request_pty(channel);
    if(ret != SSH_OK) {
        printf("ssh_channel_request_pty failed %s\n", ssh_get_error(ssh));
        return SSH_ERROR;
    }
    ret = ssh_channel_change_pty_size(channel, 80, 24);
    if(ret != SSH_OK) return SSH_ERROR;

    // request a shell
    ret = ssh_channel_request_shell(channel);
    if(ret != SSH_OK) return SSH_ERROR;

    char buffer[4069];
    int nbytes, nwritten;

    while(ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
        struct timeval timeout;
        ssh_channel in_channels[2], out_channels[2];
        fd_set fds;
        int maxfd;

        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        in_channels[0] = channel;
        in_channels[1] = NULL;

        FD_ZERO(&fds);
        FD_SET(0, &fds);

        FD_SET(ssh_get_fd(ssh), &fds);
        maxfd = ssh_get_fd(ssh) + 1;

        ssh_select(in_channels, out_channels, maxfd, &fds, &timeout);

        if(out_channels[0] != NULL) {
            nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
            if(nbytes < 0) {
                return SSH_ERROR;
            }
            if(nbytes > 0) {
                nwritten = write(1, buffer, nbytes);
                if(nwritten != nbytes) return SSH_ERROR;
            }
        }

        if(FD_ISSET(0, &fds)) {
            nbytes = read(0, buffer, sizeof(buffer));
            if(nbytes < 0) return SSH_ERROR;
            if(nbytes > 0) {
                nwritten = ssh_channel_write(channel, buffer, nbytes);
                if(nwritten != nbytes) return SSH_ERROR;
            }
        }           
        
    }

    return SSH_OK;
}


ssh_session Shell::getNewSession() {
    
    ssh_session ssh = ssh_new();
    int i {};
    if(!ssh) {
        std::cerr <<"-| [~]Failed to create SSH session\n";
        return NULL;
    }
    ssh_options_set(ssh, SSH_OPTIONS_HOST, host.c_str());
    ssh_options_set(ssh, SSH_OPTIONS_PORT, &port);
    ssh_options_set(ssh, SSH_OPTIONS_USER, username.c_str());
connect:
    i++;
    int ret = ssh_connect(ssh);

    if (ret != SSH_OK) {
        if (i < 3)
            goto connect;

        std::cerr << "-| [~]Failed to establish a connection\n";
        std::cerr << "-| [~]" << ssh_get_error(ssh) << std::endl;
        exit(1);
    }

    return ssh;
}

// sets a session
ssh_session Shell::getSSH() { return ssh; }