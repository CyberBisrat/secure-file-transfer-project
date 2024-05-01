#include "maybe.h"
#include "types.h"
#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <tuple>
#include <unistd.h>

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
error "Missing the <filesystem> header."
#endif

using namespace std;

#ifndef utils_h
#define utils_h

#define GREEN "\033[1;32m"
#define RED "\033[1;31m"
#define BLUE "\033[1;34m"
#define RESET "\033[0m"

void print_debug(unsigned char *x, int len);

const EVP_CIPHER *get_symmetric_cipher();
int get_symmetric_key_length();
int get_iv_len();
int get_block_size();

const EVP_MD *get_hash_type();
int get_hash_type_length();
int get_signature_max_length(EVP_PKEY *privkey);

/*
 * Key derivation function: given a shared secret, its length, and the required
 * length of the key, gets a key from the shared secret of the specified length.
 * The caller is responsible for the de-allocation of the key memory, and it
 * must be freed using `delete[]`
 */
Maybe<unsigned char *> kdf(unsigned char *shared_secret, int shared_secret_len,
                           unsigned int key_len);

/*
 * The caller is responsible for the de-allocation of the returned pointer, if
 * any
 */
Maybe<unsigned char *> gen_iv();

/*
 * The caller is responsible for the de-allocation of the returned pointer, if
 * any
 */
#define DUMMY_LEN 12
Maybe<unsigned char *> get_dummy();

Maybe<mtypes> get_mtype(int socket);

Maybe<bool> send_header(int socket, mtypes type);
Maybe<bool> send_header(int socket, mtypes type, seqnum seq_num, uchar *iv,
                        int iv_len);
Maybe<bool> send_tag(int socket, unsigned char *tag);

Maybe<bool> send_field(int socket, flen len, unsigned char *data);
Maybe<tuple<flen, unsigned char *>> read_field(int socket);

unsigned char mtype_to_uc(mtypes m);
Maybe<tuple<seqnum, unsigned char *>> read_header(int socket);
Maybe<unsigned char *> read_tag(int socket);

unsigned char *string_to_uchar(const string &my_string);

/* Returns the path to the user storage */
fs::path get_user_storage_path(char *username);

/*
 * Used to validate paths taken by the user.
 * Checks for path traversals
 */
bool is_path_valid(char *username, fs::path user_path);

const char *mtypes_to_string(mtypes m);

void send_error_response(int sock, unsigned char *key, const char *msg);

#endif
