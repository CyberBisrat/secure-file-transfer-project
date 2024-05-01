#include "../../common/errors.h"
#include "../../common/seq.h"
#include "../../common/types.h"
#include "../../common/utils.h"
#include "download.h"
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

Maybe<fs::path> validate_path(char *username, char *f) {
    Maybe<fs::path> res;
    fs::path f_path = f;

    // Validate path
    fs::path dest_path = get_user_storage_path(username) / f_path.filename();
    if (!is_path_valid(username, dest_path)) {
        res.set_error("Error - Illegal path");
        return res;
    }

    // check if file already exists
    if (fs::exists(dest_path)) {
        res.set_error("Error - File already exist");
        return res;
    }

    res.set_result(dest_path);
    return res;
}

void upload(int sock, unsigned char *key, char *username) {

    // -----------receive client upload request-----------
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

    unsigned char header = mtype_to_uc(UploadReq);

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
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

    if (EVP_DecryptFinal(ctx, pt + len, &len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
    }

    delete[] ct;
    delete[] tag;

    EVP_CIPHER_CTX_reset(ctx);

    inc_seqnum();

    // -----------validate client's request and answer-----------
    auto validation_res = validate_path(username, reinterpret_cast<char *>(pt));

    delete[] pt;

    if (validation_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        send_error_response(sock, key, validation_res.error);
        return;
    }

    // Generate iv for message
    auto iv_res = gen_iv();
    if (iv_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors(iv_res.error);
    }
    iv = iv_res.result;

    auto send_packet_header_res =
        send_header(sock, UploadAns, seq_num, iv, get_iv_len());
    if (send_packet_header_res.is_error) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors(send_packet_header_res.error);
    }

    // Initialize encryption context
    len = 0;
    ct_len = 0;

    if (EVP_EncryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // Authenticate data
    err = 0;
    header = mtype_to_uc(UploadAns);
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, &header, sizeof(unsigned char));
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));
    if (err != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    unsigned char response[] = "The file can be uploaded";
    ct = new unsigned char[sizeof(response)];
    if (EVP_EncryptUpdate(ctx, ct, &len, response, sizeof(response)) != 1) {
        delete[] iv;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len = len;

    if (EVP_EncryptFinal(ctx, ct + len, &len) != 1) {
        delete[] iv;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len += len;

    tag = new unsigned char[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    delete[] iv;
    EVP_CIPHER_CTX_reset(ctx);

    auto ct_send_res = send_field(sock, (flen)ct_len, ct);
    if (ct_send_res.is_error) {
        delete[] ct;
        delete[] tag;
        handle_errors(ct_send_res.error);
    }
    delete[] ct;

    auto tag_send_res = send_tag(sock, tag);
    if (tag_send_res.is_error) {
        delete[] tag;
        handle_errors(tag_send_res.error);
    }
    delete[] tag;

    inc_seqnum();

    //------------------Client's response------------------

    pt = new unsigned char[CHUNK_SIZE + get_block_size()];
    fs::path output_file_path = validation_res.result;
    FILE *output_file_fp = fopen(output_file_path.native().c_str(), "w");
    unsigned long received_size = 0;
    for (;;) {
        auto server_response_header_res = get_mtype(sock);
        if (server_response_header_res.is_error) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file_fp);
            delete[] pt;
            handle_errors(server_response_header_res.error);
        }
        auto server_response_header = server_response_header_res.result;

        // Read IV and sequence number
        server_header_res = read_header(sock);
        if (server_header_res.is_error) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file_fp);
            delete[] pt;
            handle_errors(server_header_res.error);
        }
        auto [in_seq, in_iv] = server_header_res.result;
        seq = in_seq;
        iv = in_iv;

        // Check correctness of the sequence number
        if (seq != seq_num) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file_fp);
            delete[] pt;
            delete[] iv;
            handle_errors("Incorrect sequence number");
        }

        // Read ciphertext
        ct_res = read_field(sock);
        if (ct_res.is_error) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file_fp);
            delete[] pt;
            delete[] iv;
            handle_errors(ct_res.error);
        }
        auto ct_tuple = ct_res.result;
        ct_len = get<0>(ct_tuple);
        ct = get<1>(ct_tuple);

        if (ct_len > CHUNK_SIZE + get_block_size()) {
            handle_errors("Ciphertext longer than expected");
        }

        // Read tag
        tag_res = read_tag(sock);
        if (tag_res.is_error) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file_fp);
            delete[] pt;
            delete[] ct;
            delete[] iv;
            handle_errors(tag_res.error);
        }
        tag = tag_res.result;

        // Initialize decryption
        if (EVP_DecryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file_fp);
            delete[] pt;
            delete[] tag;
            delete[] ct;
            delete[] iv;
            handle_errors();
        }
        delete[] iv;

        header = mtype_to_uc(server_response_header);

        // Authenticated data
        err = 0;
        err |= EVP_DecryptUpdate(ctx, nullptr, &len, &header, sizeof(mtype));
        err |= EVP_DecryptUpdate(ctx, nullptr, &len, seqnum_to_uc(),
                                 sizeof(seqnum));

        if (err != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file_fp);
            delete[] pt;
            delete[] tag;
            delete[] ct;
            handle_errors();
        }

        int pt_len;
        if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file_fp);
            delete[] pt;
            delete[] tag;
            delete[] ct;
            handle_errors();
        }
        pt_len = len;

        // GCM tag check
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

        if (EVP_DecryptFinal(ctx, pt + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file_fp);
            delete[] pt;
            delete[] tag;
            delete[] ct;
            handle_errors();
        }
        pt_len += len;

        delete[] ct;
        delete[] tag;

        // Reset the context and increment the sequence number
        EVP_CIPHER_CTX_reset(ctx);
        inc_seqnum();

        received_size += pt_len;
        if (received_size > FSIZE_MAX) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file_fp);
            delete[] pt;
            if (fs::exists(output_file_path)) {
                fs::remove(output_file_path);
            }
            handle_errors("Error - File too big");
        }

        // Finally, handle the message
        switch (server_response_header) {
        case UploadChunk:
        case UploadEnd:
            if (fwrite(pt, sizeof(*pt), pt_len, output_file_fp) !=
                (unsigned int)pt_len) {
                EVP_CIPHER_CTX_free(ctx);
                fclose(output_file_fp);
                delete[] pt;
                if (fs::exists(output_file_path)) {
                    fs::remove(output_file_path);
                }
                handle_errors("Error when writing uploaded chunk to file");
            }
            break;
        case Error:
        default:
            // There was an error, either prior to the upload or during it
            // Handle it by:
            //   - printing the error to the user
            //   - freeing memory
            //   - removing the (partial) uploaded file

            cout << pt << endl;

            fclose(output_file_fp);
            EVP_CIPHER_CTX_free(ctx);
            delete[] pt;

            if (fs::exists(output_file_path)) {
                fs::remove(output_file_path);
            }

            return;
        }

        if (server_response_header == UploadEnd) {
            break;
        }
    }

    EVP_CIPHER_CTX_reset(ctx);
    fclose(output_file_fp);
    delete[] pt;

#ifdef DEBUG
    cout << "File saved locally as '" << output_file_path << "' correctly!"
         << endl;
#endif

    //---------------Send response----------------

    // Generate iv for message
    iv_res = gen_iv();
    if (iv_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors(iv_res.error);
    }
    iv = iv_res.result;
    // Send upload request
    send_packet_header_res =
        send_header(sock, UploadRes, seq_num, iv, get_iv_len());
    if (send_packet_header_res.is_error) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors(send_packet_header_res.error);
    }

    if (EVP_EncryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // Authenticated data
    err = 0;
    header = mtype_to_uc(UploadRes);
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, &header, sizeof(unsigned char));
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));
    if (err != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // Encryption of the filename
    unsigned char response2[] = "File uploaded correctly";
    ct = new unsigned char[sizeof(response2) + get_block_size()];
    if (EVP_EncryptUpdate(ctx, ct, &len, response2, sizeof(response2)) != 1) {
        delete[] iv;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len = len;

    if (EVP_EncryptFinal(ctx, ct + ct_len, &len) != 1) {
        delete[] iv;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len += len;

    tag = new unsigned char[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    delete[] iv;
    EVP_CIPHER_CTX_free(ctx);

    // Send ciphertext
    ct_send_res = send_field(sock, (flen)ct_len, ct);
    if (ct_send_res.is_error) {
        delete[] ct;
        delete[] tag;
        handle_errors(ct_send_res.error);
    }
    delete[] ct;

    tag_send_res = send_tag(sock, tag);
    if (tag_send_res.is_error) {
        delete[] tag;
        handle_errors(tag_send_res.error);
    }
    delete[] tag;

    inc_seqnum();
}
