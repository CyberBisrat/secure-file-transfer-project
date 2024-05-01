#include "../../common/errors.h"
#include "../../common/seq.h"
#include "../../common/types.h"
#include "../../common/utils.h"
#include <openssl/evp.h>
#include <string.h>

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

Maybe<FILE *> validate_request(char *username, char *filename) {
    Maybe<FILE *> res;

    fs::path filename_path = get_user_storage_path(username) / filename;
    if (!is_path_valid(username, filename_path)) {
        res.set_error("Error - Illegal filename");
        return res;
    }

    if (!fs::exists(filename_path)) {
        res.set_error("Error - File not found");
        return res;
    }

    res.result = fopen(filename_path.native().c_str(), "r");
    if (res.result == nullptr) {
        res.set_error("Error - File is not readable");
    }

    return res;
}

void download(int sock, unsigned char *key, char *username) {

    // -----------receive client download request-----------
    auto server_header_res = read_header(sock);
    if (server_header_res.is_error) {
        handle_errors();
    }
    auto [seq, iv] = server_header_res.result;

    if (seq != seq_num) {
        delete[] iv;
        handle_errors("Incorrect sequence number");
    }

    // Read ciphertext
    auto ct_res = read_field(sock);
    if (ct_res.is_error) {
        delete[] iv;
        handle_errors();
    }
    auto [ct_len, ct] = ct_res.result;

    // Read tag
    auto tag_res = read_tag(sock);
    if (tag_res.is_error) {
        delete[] ct;
        delete[] iv;
        handle_errors();
    }
    auto tag = tag_res.result;

    // Initialize decryption
    EVP_CIPHER_CTX *ctx;
    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        handle_errors("Could not decrypt message (alloc)");
    }
    int len;

    if (EVP_DecryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    delete[] iv;

    unsigned char header = mtype_to_uc(DownloadReq);

    // Authenticated data
    int err = 0;
    err |= EVP_DecryptUpdate(ctx, nullptr, &len, &header, sizeof(mtype));
    err |=
        EVP_DecryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));

    if (err != 1) {
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    auto *pt = new unsigned char[ct_len];
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

    if (EVP_DecryptFinal(ctx, pt + len, &len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    delete[] ct;
    delete[] tag;

    EVP_CIPHER_CTX_reset(ctx);

    inc_seqnum();

    // -----------validate client's request and answer-----------
    auto validation_res =
        validate_request(username, reinterpret_cast<char *>(pt));
    delete[] pt;
    if (validation_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        send_error_response(sock, key, validation_res.error);
        return;
    }

    FILE *file_fp = validation_res.result;

    // Send the file a chunk at a time
    unsigned char buffer[CHUNK_SIZE] = {0};
    ct = new unsigned char[sizeof(buffer) + get_block_size()];
    tag = new unsigned char[TAG_LEN];
    mtypes msg_type = DownloadChunk;

    for (;;) {
        size_t read_len;
        if ((read_len = fread(buffer, sizeof(*buffer), sizeof(buffer),
                              file_fp)) != sizeof(buffer)) {

            // When we read less than expected we could either have an error, or
            // we could have reached eof
            if (feof(file_fp) != 0) {
                // Change message type, as this is the last chunk of data
                msg_type = DownloadEnd;
            } else if (ferror(file_fp) != 0) {
                delete[] ct;
                delete[] tag;
                fclose(file_fp);
                EVP_CIPHER_CTX_free(ctx);
                send_error_response(sock, key, "Error - Could not read file");
                return;
            } else {
                delete[] ct;
                delete[] tag;
                fclose(file_fp);
                EVP_CIPHER_CTX_free(ctx);
                send_error_response(sock, key, "Error - Cosmic rays uh?");
                return;
            }
        }

        // Generate iv for message
        auto iv_res = gen_iv();
        if (iv_res.is_error) {
            delete[] ct;
            delete[] tag;
            fclose(file_fp);
            EVP_CIPHER_CTX_free(ctx);
            handle_errors(iv_res.error);
        }
        iv = iv_res.result;

        // Send chunk header
        auto send_packet_header_res =
            send_header(sock, msg_type, seq_num, iv, get_iv_len());
        if (send_packet_header_res.is_error) {
            delete[] iv;
            delete[] ct;
            delete[] tag;
            fclose(file_fp);
            EVP_CIPHER_CTX_free(ctx);
            handle_errors(send_packet_header_res.error);
        }

        if (EVP_EncryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
            delete[] iv;
            delete[] ct;
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            fclose(file_fp);
            handle_errors();
        }
        delete[] iv;

        // Authenticated data
        err = 0;
        header = mtype_to_uc(msg_type);
        err |= EVP_EncryptUpdate(ctx, nullptr, &len, &header,
                                 sizeof(unsigned char));
        err |= EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(),
                                 sizeof(seqnum));
        if (err != 1) {
            delete[] ct;
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            fclose(file_fp);
            handle_errors();
        }

        // Encrypt the chunk
        if (EVP_EncryptUpdate(ctx, ct, &len, buffer, read_len) != 1) {
            delete[] ct;
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            fclose(file_fp);
            handle_errors();
        }
        ct_len = len;

        // Finalize encryption
        if (EVP_EncryptFinal(ctx, ct + ct_len, &len) != 1) {
            delete[] ct;
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            fclose(file_fp);
            handle_errors();
        }
        ct_len += len;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) !=
            1) {
            delete[] ct;
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            fclose(file_fp);
            handle_errors();
        }

        // Send ciphertext
        auto ct_send_res = send_field(sock, (flen)ct_len, ct);
        if (ct_send_res.is_error) {
            delete[] ct;
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            fclose(file_fp);
            handle_errors(ct_send_res.error);
        }

        auto tag_send_res = send_tag(sock, tag);
        if (tag_send_res.is_error) {
            delete[] tag;
            delete[] ct;
            EVP_CIPHER_CTX_free(ctx);
            fclose(file_fp);
            handle_errors(tag_send_res.error);
        }

        // At the end, reset the context and increase the sequence number
        EVP_CIPHER_CTX_reset(ctx);
        inc_seqnum();

        // We have reached EOF, thus the download has ended
        // Note that we already sent the full file to the client, correctly
        // ending with a DownloadEnd message
        if (feof(file_fp) != 0) {
            break;
        }
    }

    delete[] tag;
    delete[] ct;
    EVP_CIPHER_CTX_free(ctx);
    fclose(file_fp);
}
