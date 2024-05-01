#include "utils.h"
#include "errors.h"
#include "seq.h"
#include "types.h"
#include <errno.h>
#include <iostream>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
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

void print_debug(unsigned char *x, int len) {
    for (int i = 0; i < len; i++)
        printf("%02x", (int)x[i]);
}

const EVP_CIPHER *get_symmetric_cipher() { return EVP_aes_256_gcm(); }
int get_iv_len() { return EVP_CIPHER_iv_length(get_symmetric_cipher()); }
int get_block_size() { return EVP_CIPHER_block_size(get_symmetric_cipher()); }

int get_symmetric_key_length() {
    auto cipher = get_symmetric_cipher();
    return EVP_CIPHER_key_length(cipher);
}

const EVP_MD *get_hash_type() { return EVP_sha256(); }
int get_hash_type_length() { return EVP_MD_size(get_hash_type()); }
int get_signature_max_length(EVP_PKEY *privkey) {
    return EVP_PKEY_size(privkey);
}

Maybe<unsigned char *> kdf(unsigned char *shared_secret, int shared_secret_len,
                           unsigned int key_len) {
    Maybe<unsigned char *> res;

    unsigned char *digest = new unsigned char[get_hash_type_length()];
    unsigned int digest_len;
    EVP_MD_CTX *ctx;
    if ((ctx = EVP_MD_CTX_new()) == nullptr ||
        EVP_DigestInit(ctx, get_hash_type()) != 1 ||
        EVP_DigestUpdate(ctx, shared_secret, shared_secret_len) != 1 ||
        EVP_DigestFinal(ctx, digest, &digest_len) != 1) {
        delete[] digest;
        delete[] shared_secret;
        explicit_bzero(shared_secret, shared_secret_len);
        EVP_MD_CTX_free(ctx);
        res.set_error("Could not create hashing context for kdf");
        return res;
    }

    explicit_bzero(shared_secret, shared_secret_len);
    delete[] shared_secret;
    EVP_MD_CTX_free(ctx);

    if (digest_len < key_len) {
        delete[] digest;
        res.set_error("Cannot derive a key: key length is bigger than the "
                      "digest's length.");
        return res;
    }

    unsigned char *key = new unsigned char[key_len];
    memcpy(key, digest, key_len);
    explicit_bzero(digest, digest_len);
    delete[] digest;

    res.set_result(key);
    return res;
}

Maybe<unsigned char *> gen_iv() {
    Maybe<unsigned char *> res;

    int iv_len = get_iv_len();
    if (RAND_poll() != 1) {
        res.set_error("Could not seed generator");
        return res;
    }

    unsigned char *iv = new unsigned char[iv_len];
    if (RAND_bytes(iv, iv_len) != 1) {
        delete[] iv;
        res.set_error("Could not generate IV");
    } else {
        res.set_result(iv);
    }
    return res;
}

Maybe<unsigned char *> get_dummy() {
    Maybe<unsigned char *> res;

    if (RAND_poll() != 1) {
        res.set_error("Could not seed generator");
        return res;
    }

    unsigned char *dummy = new unsigned char[DUMMY_LEN];
    if (RAND_bytes(dummy, DUMMY_LEN) != 1) {
        delete[] dummy;
        res.set_error("Could not generate dummy");
    } else {
        res.set_result(dummy);
    }
    return res;
}

Maybe<mtypes> get_mtype(int socket) {
    Maybe<mtypes> res;

    if (read(socket, &res.result, sizeof(mtype)) != sizeof(mtype)) {
        res.set_error("Error when reading mtype");
    };

#ifdef DEBUG
    cout << endl
         << GREEN << "Message type: " << mtypes_to_string(res.result) << RESET
         << endl;
#endif
    return res;
}

Maybe<bool> send_header(int socket, mtypes type) {
    Maybe<bool> res;
    if (write(socket, &type, sizeof(mtype)) != sizeof(mtype)) {
        res.set_error("Error when writing mtype");
        return res;
    }
#ifdef DEBUG
    cout << endl
         << BLUE << "Message type: " << mtypes_to_string(mtypes(type)) << RESET
         << endl;
#endif
    return res;
}

Maybe<bool> send_header(int socket, mtypes type, seqnum seq_num, uchar *iv,
                        int iv_len) {
    auto res = send_header(socket, type);
    if (res.is_error) {
        return res;
    }

    if (write(socket, &seq_num, sizeof(seq_num)) != sizeof(seq_num)) {
        res.set_error("Error when writing sequence number");
        return res;
    }

#ifdef DEBUG
    cout << BLUE << "Sequence number: " << seq_num << RESET << endl;
#endif

    if (write(socket, iv, iv_len) != iv_len) {
        res.set_error("Error when writing iv");
        return res;
    };

#ifdef DEBUG
    cout << BLUE << "IV: ";
    print_debug(iv, iv_len);
    cout << RESET << endl;
#endif

    return res;
}
Maybe<bool> send_tag(int socket, unsigned char *tag) {
    Maybe<bool> res;
    if (write(socket, tag, TAG_LEN) != TAG_LEN) {
        res.set_error("Error when writing tag");
        return res;
    }

    return res;
}

Maybe<bool> send_field(int socket, flen len, unsigned char *data) {
    Maybe<bool> res;
    if (write(socket, &len, sizeof(flen)) != sizeof(flen)) {
        res.set_error("Error when writing field length");
        return res;
    }

#ifdef DEBUG
    cout << BLUE << "Field length: " << len << RESET << endl;
#endif
    if (write(socket, data, len) != len) {
        res.set_error("Error when writing field data");
        return res;
    }

#ifdef DEBUG
    cout << BLUE << "Content (hex): ";
    print_debug(data, len);
    cout << RESET << endl;
#endif
    return res;
}

Maybe<tuple<flen, unsigned char *>> read_field(int socket) {
    Maybe<tuple<flen, unsigned char *>> res;

    ssize_t received_len = 0;
    ssize_t read_len;
    flen len;
    while ((unsigned long)received_len < sizeof(flen)) {
        if ((read_len = read(socket, (uchar *)&len + received_len,
                             sizeof(flen) - received_len)) <= 0) {
            res.set_error("Error when reading field length");
            return res;
        }
        received_len += read_len;
    }

#ifdef DEBUG

    cout << GREEN << "Field length: " << len << RESET << endl;
#endif
    unsigned char *r = new unsigned char[len];

    received_len = 0;
    while (received_len < len) {
        if ((read_len = read(socket, r + received_len, len - received_len)) <=
            0) {
            delete[] r;
            res.set_error("Error when reading field");
            return res;
        }
        received_len += read_len;
    }

#ifdef DEBUG
    cout << GREEN << "Content (hex): ";
    print_debug(reinterpret_cast<unsigned char *>(r), len);
    cout << endl << RESET;
#endif

    res.set_result({len, r});
    return res;
}

unsigned char mtype_to_uc(mtypes m) { return (unsigned char)m; }

Maybe<tuple<seqnum, unsigned char *>> read_header(int socket) {
    Maybe<tuple<seqnum, unsigned char *>> res;

    ssize_t received_len = 0;
    ssize_t read_len;
    seqnum seq;
    while ((unsigned long)received_len < sizeof(seqnum)) {
        if ((read_len = read(socket, (uchar *)&seq + received_len,
                             sizeof(seqnum) - received_len)) <= 0) {
            res.set_error("Error when reading sequence number");
            return res;
        }
        received_len += read_len;
    }

#ifdef DEBUG
    cout << GREEN << "Sequence number: " << seq << RESET << endl;
#endif

    received_len = 0;
    unsigned char *iv = new unsigned char[get_iv_len()];
    while (received_len < get_iv_len()) {
        if ((read_len = read(socket, iv + received_len,
                             get_iv_len() - received_len)) <= 0) {
            delete[] iv;
            res.set_error("Error when reading iv");
            return res;
        }

        received_len += read_len;
    }

#ifdef DEBUG
    cout << GREEN << "IV: ";
    print_debug(iv, get_iv_len());
    cout << RESET << endl;
#endif

    res.set_result({seq, iv});
    return res;
}

Maybe<unsigned char *> read_tag(int socket) {
    Maybe<unsigned char *> res;

    ssize_t received_len = 0;
    ssize_t read_len;
    unsigned char *tag = new unsigned char[TAG_LEN];
    while ((unsigned long)received_len < TAG_LEN) {
        if ((read_len = read(socket, tag + received_len,
                             TAG_LEN - received_len)) <= 0) {
            res.set_error("Error when reading tag");
            return res;
        }
        received_len += read_len;
    }

    res.set_result(tag);
    return res;
}

unsigned char *string_to_uchar(const string &s) {
    unsigned char *res = new unsigned char[s.length() + 1];
    memcpy(res, s.c_str(), s.length() + 1);
    return res;
}

fs::path get_user_storage_path(char *username) {
    return fs::current_path() / "server" / "storage" / username;
}

bool is_path_valid(char *username, fs::path user_path) {
    fs::path ok_path = get_user_storage_path(username);
    string user_path_canonical_str;
#if __has_include(<filesystem>)
    fs::path user_path_canonical = fs::weakly_canonical(user_path);
    user_path_canonical_str = user_path_canonical;
#else
    // realpath cannot be used on non-existing files, therefore we:
    //   - check if the file already exists. If not, try to create the file, if
    //   it fails it's invalid
    //   - use realpath to get the canonical path
    //   - remove the file, if we created it earlier
    //   - check that the canonical path is a file in the user storage
    bool already_exists;
    if (!(already_exists = fs::exists(user_path))) {
        FILE *f;
        if ((f = fopen(user_path.native().c_str(), "w")) == nullptr) {
            return false;
        }
        fclose(f);
    }

    char *user_path_canonical = realpath(user_path.native().c_str(), nullptr);
    if (!already_exists)
        fs::remove(user_path);

    if (user_path_canonical == nullptr)
        return false;

    user_path_canonical_str = user_path_canonical;
#endif
    return user_path_canonical_str.rfind(ok_path.native(), 0) == 0;
}

const char *mtypes_to_string(mtypes m) {
    switch (m) {
    case AuthStart:
        return "AuthStart";
    case AuthServerAns:
        return "AuthServerAns";
    case AuthClientAns:
        return "AuthClientAns";
    case UploadReq:
        return "UploadReq";
    case UploadAns:
        return "UploadAns";
    case UploadChunk:
        return "UploadChunk";
    case UploadEnd:
        return "UploadEnd";
    case UploadRes:
        return "UploadRes";
    case DownloadReq:
        return "DownloadReq";
    case DownloadChunk:
        return "DownloadChunk";
    case DownloadEnd:
        return "DownloadEnd";
    case DeleteReq:
        return "DeleteReq";
    case DeleteConfirm:
        return "DeleteConfirm";
    case DeleteAns:
        return "DeleteAns";
    case DeleteRes:
        return "DeleteRes";
    case ListReq:
        return "ListReq";
    case ListAns:
        return "ListAns";
    case RenameReq:
        return "RenameReq";
    case RenameAns:
        return "RenameAns";
    case LogoutReq:
        return "LogoutReq";
    case LogoutAns:
        return "LogoutAns";
    case Error:
        return "Error";
    default:
        return "Cosmic rays uh?";
    }
}

void send_error_response(int sock, unsigned char *key, const char *msg) {
    // Generate iv for message
    auto iv_res = gen_iv();
    if (iv_res.is_error) {
        handle_errors(iv_res.error);
    }
    auto iv = iv_res.result;

    // Send download request
    auto send_packet_header_res =
        send_header(sock, Error, seq_num, iv, get_iv_len());
    if (send_packet_header_res.is_error) {
        delete[] iv;
        handle_errors(send_packet_header_res.error);
    }

    // Initialize encryption context
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ct_len;
    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        delete[] iv;
        handle_errors("Could not encrypt message (alloc)");
    }

    if (EVP_EncryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    delete[] iv;

    // Authenticated data
    int err = 0;
    unsigned char header = mtype_to_uc(Error);
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, &header, sizeof(unsigned char));
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));
    if (err != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // Encryption of the filename
    unsigned char *ct = new unsigned char[FNAME_MAX_LEN + get_block_size()];
    if (EVP_EncryptUpdate(
            ctx, ct, &len,
            reinterpret_cast<unsigned char *>(const_cast<char *>(msg)),
            strlen(msg) + 1) != 1) {
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len = len;

    if (EVP_EncryptFinal(ctx, ct + ct_len, &len) != 1) {
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len += len;

    unsigned char *tag = new unsigned char[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) != 1) {
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    EVP_CIPHER_CTX_free(ctx);

    // Send ciphertext
    auto ct_send_res = send_field(sock, (flen)ct_len, ct);
    if (ct_send_res.is_error) {
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors(ct_send_res.error);
    }
    delete[] ct;

    auto tag_send_res = send_tag(sock, tag);
    if (tag_send_res.is_error) {
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors(tag_send_res.error);
    }
    delete[] tag;

    inc_seqnum();
}
