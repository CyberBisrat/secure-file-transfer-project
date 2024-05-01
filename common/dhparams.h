#include <openssl/dh.h>

#ifndef dhparams_h
#define dhparams_h

DH *get_dh2048();
EVP_PKEY *gen_keypair();
#endif