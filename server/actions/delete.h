#ifndef delete_h
#define delete_h

void delete_file(int sock, unsigned char *key, char *username);

int sanitize_path(char *username, unsigned char *f);

#endif