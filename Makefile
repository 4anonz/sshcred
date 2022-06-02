compile:
	g++ -c src/sshcred.cpp
	g++ -c src/shell/shell.cpp
	g++ src/main.cpp sshcred.o shell.o -lssh -o $(PREFIX)/bin/sshcred
	rm -rf sshcred.o rm shell.o
