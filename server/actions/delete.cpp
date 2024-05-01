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

Maybe<fs::path> sanitize_path(char *username, unsigned char *f) {
    Maybe<fs::path> res;

    // Validate path
    fs::path f_path =
        get_user_storage_path(username) / reinterpret_cast<char *>(f);

    if (!is_path_valid(username, f_path)) {
        res.set_error("Error - Illegal path");
        return res;
    }

    // Check if file exists
    if (!fs::exists(f_path)) {
        res.set_error("Error - File doesn't exist");
        return res;
    }

    res.set_result(f_path);
    return res;
}

string actual_delete(fs::path f_path) {
    error_code ec;
    int retval = fs::remove(f_path, ec);
    if (!ec) { // Success
        if (retval) {
            return "Deletion performed correctly";
        } else {
            return "File does not exist, but it should";
        }
    } else { // Error
        return "Deletion canceled - something went wrong";
    }
    return "Deletion canceled - something went wrong";
}

void delete_file(int sock, unsigned char *key, char *username) {

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

    unsigned char header = mtype_to_uc(DeleteReq);

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
    // Decrypt Update
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
    }

    // GCM tag check
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

    // Decrypt Final. Finalize the encryption and adds the padding
    if (EVP_DecryptFinal(ctx, pt + len, &len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
    }

    // free variables
    delete[] ct;
    delete[] tag;

    // free context
    EVP_CIPHER_CTX_reset(ctx);

    inc_seqnum();

#ifdef DEBUG
    cout << endl << "f to delete: " << pt << endl;
#endif

    // Plaintext stored in filename variable
    unsigned char *filename = pt;

    // Sanitize path
    auto sanitize_res = sanitize_path(username, filename);
    if (sanitize_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        send_error_response(sock, key, sanitize_res.error);
        delete[] filename;
        return;
    }

    //-----------------Respond to client---------------------

    // Generate iv for message
    auto iv_res = gen_iv();
    if (iv_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors(iv_res.error);
    }
    iv = iv_res.result;

    auto send_packet_header_res =
        send_header(sock, DeleteConfirm, seq_num, iv, get_iv_len());
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
    header = mtype_to_uc(DeleteConfirm);
    err |= EVP_EncryptUpdate(ctx, nullptr, &len, &header, sizeof(mtype));
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));
    if (err != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    unsigned char response[] = "Are you sure? (y/n)";
    ct = new unsigned char[sizeof(response) + get_block_size()];
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

    //---------------Wait client confirmation---------------------

    auto mtype_res = get_mtype(sock);
    if (mtype_res.is_error || mtype_res.result != DeleteRes) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors("Incorrect message type");
    }

    server_header_res = read_header(sock);
    if (server_header_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    seq = get<0>(server_header_res.result);
    iv = get<1>(server_header_res.result);

    if (seq != seq_num) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] iv;
        handle_errors("Incorrect sequence number");
    }

    // read ciphertext
    ct_res = read_field(sock);
    if (ct_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] iv;
        handle_errors();
    }
    ct_len = get<0>(ct_res.result);
    ct = get<1>(ct_res.result);
    pt = new unsigned char[ct_len];

    // read tag
    tag_res = read_tag(sock);
    if (tag_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] ct;
        delete[] pt;
        delete[] iv;
        handle_errors();
    }
    tag = tag_res.result;

    if (EVP_DecryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    delete[] iv;

    header = mtype_to_uc(DeleteRes);

    /* Specify authenticated data */
    err = 0;
    err |= EVP_DecryptUpdate(ctx, nullptr, &len, &header, sizeof(mtype));
    err |=
        EVP_DecryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));

    if (err != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // Decrypt Update
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // GCM tag check
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

    // Decrypt Final. Finalize the encryption and adds the padding
    if (EVP_DecryptFinal(ctx, pt + len, &len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // free variables
    delete[] ct;
    delete[] tag;

    // free context
    EVP_CIPHER_CTX_reset(ctx);

    inc_seqnum();

    // Perform actual deletion
    string delete_response;
    if (strncmp(reinterpret_cast<char *>(pt), "y", 1) == 0) {
        delete_response = actual_delete(sanitize_res.result);
    } else {
        delete_response = "Deletion aborted - user did not confirm";
    }
    delete[] pt;
    delete[] filename;

    //-----------------Respond to client---------------------

    // Generate iv for message
    iv_res = gen_iv();
    if (iv_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors(iv_res.error);
    }
    iv = iv_res.result;

    send_packet_header_res =
        send_header(sock, DeleteAns, seq_num, iv, get_iv_len());
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
    header = mtype_to_uc(DeleteAns);
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, &header, sizeof(unsigned char));
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));
    if (err != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    pt_len = delete_response.length() + 1;
    pt = string_to_uchar(delete_response);
    ct = new unsigned char[pt_len];
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) != 1) {
        delete[] iv;
        delete[] pt;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len = len;
    delete[] pt;

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
