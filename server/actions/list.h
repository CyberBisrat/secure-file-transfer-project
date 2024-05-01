#include <tuple>
using namespace std;

#ifndef list_h
#define list_h

tuple<unsigned char *, unsigned int> get_file_list(char *username);

void list_files(int sock, unsigned char *key, char *username);

#endif