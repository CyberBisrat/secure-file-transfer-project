#include "../../common/maybe.h"
#include <string>

#ifndef rename_h
#define rename_h

void rename(int sock, unsigned char *key, char *username);

// TODO: better type?
int handle_renaming(unsigned char *msg, int msg_len, char *username);

bool is_path_illegal(std::string path);

#endif