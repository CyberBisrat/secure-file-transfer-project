#include "../common/errors.h"
#include "../common/types.h"
#include "../common/utils.h"
#include "actions/delete.h"
#include "actions/download.h"
#include "actions/list.h"
#include "actions/logout.h"
#include "actions/rename.h"
#include "actions/upload.h"
#include "authentication.h"
#include <arpa/inet.h>
#include <iostream>
#include <openssl/bio.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define ADDRESS "127.0.0.1"

using namespace std;

int sock;
unsigned char *shared_key;

void signal_handler(int signum) {
    logout(sock, shared_key);
    explicit_bzero(shared_key, get_symmetric_key_length());
    delete[] shared_key;
    close(sock);
    exit(EXIT_SUCCESS);
}

void greet_user() {
    // Thanks to https://fsymbols.com/generators/carty/
    cout << "\
░█████╗░██╗░░░░░░█████╗░██╗░░░██╗██████╗░    ░██████╗████████╗░█████╗░██████╗░░█████╗░░██████╗░███████╗\n\
██╔══██╗██║░░░░░██╔══██╗██║░░░██║██╔══██╗    ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝░██╔════╝\n\
██║░░╚═╝██║░░░░░██║░░██║██║░░░██║██║░░██║    ╚█████╗░░░░██║░░░██║░░██║██████╔╝███████║██║░░██╗░█████╗░░\n\
██║░░██╗██║░░░░░██║░░██║██║░░░██║██║░░██║    ░╚═══██╗░░░██║░░░██║░░██║██╔══██╗██╔══██║██║░░╚██╗██╔══╝░░\n\
╚█████╔╝███████╗╚█████╔╝╚██████╔╝██████╔╝    ██████╔╝░░░██║░░░╚█████╔╝██║░░██║██║░░██║╚██████╔╝███████╗\n\
░╚════╝░╚══════╝░╚════╝░░╚═════╝░╚═════╝░    ╚═════╝░░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝░╚═════╝░╚══════╝"
         << endl
         << endl;
}

void print_menu() {
    cout << "Actions:" << endl;
    cout << "    list     - List your files" << endl;
    cout << "    upload   - Upload a new file" << endl;
    cout << "    download - Download a file" << endl;
    cout << "    rename   - Rename a file" << endl;
    cout << "    delete   - Delete a file" << endl;
    cout << "    exit     - Terminate current session" << endl;
    cout << "> ";
}

/* Loop for the user to interact with the server. */
void interact() {
    string action;
    int key_len;

    key_len = get_symmetric_key_length();

    // First of all, the user must run the authentication protocol with the
    // other party (hopefully the server). The exchange also provides a shared
    // ephemeral key to use for further communications.
    try {
        shared_key = authenticate(sock, key_len);
#ifdef DEBUG
        cout << "Shared key: ";
        print_debug(shared_key, key_len);
        cout << endl;
#endif

        // Interaction loop. The user can perform a set of actions, until he
        // decides to terminate the session.
        for (;;) {
            print_menu();
            if (!getline(cin, action)) {
                cout << "Error reading input!" << endl;
            }

            if (action == "list") {
                list_files(sock, shared_key);
            } else if (action == "upload") {
                upload(sock, shared_key);
            } else if (action == "download") {
                download(sock, shared_key);
            } else if (action == "rename") {
                rename(sock, shared_key);
            } else if (action == "delete") {
                delete_file(sock, shared_key);
            } else if (action == "exit") {
                kill(getpid(), SIGUSR1);
            } else {
                cout << "Invalid action!" << endl;
            }
        }
    } catch (char const *ex) {
        cerr << "Something went wrong! :(" << endl;
#ifdef DEBUG
        cerr << "Error: " << ex << endl;
#endif
        cerr << "Exiting..." << endl;
        close(sock);
        exit(EXIT_FAILURE);
    }
}

int main() {
    struct sockaddr_in serv_addr;

    // Register signal handler to gracefully close on SIGINT
    signal(SIGINT, signal_handler);

    // Register signal handler to gracefully close on SIGUSR1 (before sequence
    // number wraps)
    signal(SIGUSR1, signal_handler);

    // Create the socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set socket address and port
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Cannot convert address");
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Cannot connect to server");
        exit(EXIT_FAILURE);
    }

    greet_user();

    // Start interacting with the server
    interact();

    // Close socket when we are done
    close(sock);
}
