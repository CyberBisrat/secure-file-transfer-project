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

Maybe<bool> handle_renaming(char *username, unsigned char *f_old,
                            unsigned char *f_new) {
    Maybe<bool> res;

    // Validate old and new paths
    fs::path f_old_path =
        get_user_storage_path(username) / reinterpret_cast<char *>(f_old);
    fs::path f_new_path =
        get_user_storage_path(username) / reinterpret_cast<char *>(f_new);

#ifdef DEBUG
    cout << "Old path: " << f_old_path << endl
         << "New path: " << f_new_path << endl;
#endif

    if (!is_path_valid(username, f_old_path) ||
        !is_path_valid(username, f_new_path)) {
        res.set_error("Error - Illegal path");
        return res;
    }

    // check if file exists
    if (!fs::exists(f_old_path)) {
        res.set_error("Error - File does not exist");
        return res;
    }

    // check that new filename does not exist
    if (fs::exists(f_new_path)) {
        res.set_error("Error - New filename already exists");
        return res;
    }

    // renaming
    fs::rename(f_old_path, f_new_path);

    return res;
}

void rename(int sock, unsigned char *key, char *username) {

    // -----------receive client list request-----------

    auto server_header_res = read_header(sock);
    if (server_header_res.is_error) {
        handle_errors();
    }
    auto [seq, iv] = server_header_res.result;

    if (seq != seq_num) {
        delete[] iv;
        handle_errors("Incorrect sequence number");
    }

    // read ciphertext
    auto ct_res = read_field(sock);
    if (ct_res.is_error) {
        delete[] iv;
        handle_errors();
    }
    auto [ct_len, ct] = ct_res.result;

    // read tag
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

    unsigned char header = mtype_to_uc(RenameReq);

    /* Specify authenticated data */
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
    int pt_len;
    // Encrypt Update: one call is enough because our mesage is very short.
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
    }
    pt_len = len;

    // GCM tag check
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

    // Encrypt Final. Finalize the encryption and adds the padding
    if (EVP_DecryptFinal(ctx, pt + len, &len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
    }
    pt_len += len;

    // free variables
    delete[] ct;
    delete[] tag;

    // free context
    EVP_CIPHER_CTX_reset(ctx);

    inc_seqnum();

#ifdef DEBUG
    cout << endl << "f_old || f_new: " << pt << endl;
#endif

    // handle renaming
    auto rename_res = handle_renaming(username, pt, pt + FNAME_MAX_LEN);
    if (rename_res.is_error) {
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
        send_error_response(sock, key, rename_res.error);
        return;
    }

    delete[] pt;

    //-----------------Respond to client---------------------

    // Generate iv for message
    auto iv_res = gen_iv();
    if (iv_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors(iv_res.error);
    }
    iv = iv_res.result;

    auto send_packet_header_res =
        send_header(sock, RenameAns, seq_num, iv, get_iv_len());
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
    header = mtype_to_uc(RenameAns);
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, &header, sizeof(unsigned char));
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));
    if (err != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    unsigned char response[] = "File renamed correctly";
    ct = new unsigned char[pt_len];
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
    EVP_CIPHER_CTX_free(ctx);

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
}
