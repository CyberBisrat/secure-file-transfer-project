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

void download(int sock, unsigned char *key) {

    cout << "What do you want to download? ";
    unsigned char filename[FNAME_MAX_LEN] = {0};
    if (fgets(reinterpret_cast<char *>(filename), FNAME_MAX_LEN, stdin) ==
        nullptr) {
        handle_errors();
    }
    filename[strcspn(reinterpret_cast<char *>(filename), "\n")] = '\0';

    cout << "Where do you want to save the file? ";
    char output_file[FNAME_MAX_LEN] = {0};
    if (fgets(output_file, FNAME_MAX_LEN, stdin) == nullptr) {
        handle_errors();
    }
    output_file[strcspn(output_file, "\n")] = '\0';

    // Sanity check: never overwrite a file
    if (fs::status(fs::path(output_file)).type() != fs::file_type::not_found) {
        cout << "Error - Output file must not exist" << endl;
        return;
    }

    // Make sure that the file can be written before
    FILE *output_file_fp;
    if ((output_file_fp = fopen(output_file, "w")) == nullptr) {
        cout << "Error - Could not open output file for writing" << endl;
        return;
    }

    // Generate iv for message
    auto iv_res = gen_iv();
    if (iv_res.is_error) {
        handle_errors(iv_res.error);
    }
    auto iv = iv_res.result;

    // Send download request
    auto send_packet_header_res =
        send_header(sock, DownloadReq, seq_num, iv, get_iv_len());
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

    // Authenticated data
    int err = 0;
    unsigned char header = mtype_to_uc(DownloadReq);
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
    unsigned char *ct = new unsigned char[FNAME_MAX_LEN + get_block_size()];
    if (EVP_EncryptUpdate(ctx, ct, &len, filename, FNAME_MAX_LEN) != 1) {
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

    unsigned char *tag = new unsigned char[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    delete[] iv;
    EVP_CIPHER_CTX_reset(ctx);

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

    //------------------Server's response------------------

    unsigned char *pt = new unsigned char[CHUNK_SIZE + get_block_size()];

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
        auto server_header_res = read_header(sock);
        if (server_header_res.is_error) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file_fp);
            delete[] pt;
            handle_errors(server_header_res.error);
        }
        auto [seq, in_iv] = server_header_res.result;
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
        auto ct_res = read_field(sock);
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
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file_fp);
            delete[] pt;
            delete[] iv;
            delete[] ct;
            handle_errors("Ciphertext longer than expected");
        }

        // Read tag
        auto tag_res = read_tag(sock);
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

        // Finally, handle the message
        switch (server_response_header) {
        case DownloadChunk:
        case DownloadEnd:
            if (fwrite(pt, sizeof(*pt), pt_len, output_file_fp) !=
                (unsigned int)pt_len) {
                EVP_CIPHER_CTX_free(ctx);
                fclose(output_file_fp);
                delete[] pt;
                handle_errors("Error when writing downloaded chunk to file");
            }
            break;
        case Error:
        default:
            // There was an error, either prior to the download or during it
            // Handle it by:
            //   - printing the error to the user
            //   - freeing memory
            //   - removing the (partial) downloaded file

            cout << pt << endl;

            fclose(output_file_fp);
            EVP_CIPHER_CTX_free(ctx);
            delete[] pt;

            fs::path outfile_path = fs::path(output_file);
            if (fs::exists(outfile_path)) {
                fs::remove(outfile_path);
            }

            return;
        }

        if (server_response_header == DownloadEnd) {
            break;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(output_file_fp);
    delete[] pt;

    cout << "File saved locally as '" << output_file << "' correctly!" << endl;
}
