#include "../../common/errors.h"
#include "../../common/seq.h"
#include "../../common/types.h"
#include "../../common/utils.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

void rename(int sock, unsigned char *key) {

    // all the filenames must have same size
    unsigned char f_old[FNAME_MAX_LEN] = {0};
    unsigned char f_new[FNAME_MAX_LEN] = {0};

    // get f_old
    cout << "File to rename: ";
    if (fgets(reinterpret_cast<char *>(f_old), FNAME_MAX_LEN, stdin) ==
        nullptr) {
        handle_errors();
    }
    f_old[strcspn(reinterpret_cast<char *>(f_old), "\n")] = '\0';

    // get f_new
    cout << "New name: ";
    if (fgets(reinterpret_cast<char *>(f_new), FNAME_MAX_LEN, stdin) ==
        nullptr) {
        handle_errors();
    }
    f_new[strcspn(reinterpret_cast<char *>(f_new), "\n")] = '\0';

    // Generate iv for message
    auto iv_res = gen_iv();
    if (iv_res.is_error) {
        handle_errors(iv_res.error);
    }
    auto iv = iv_res.result;

    // Send rename request
    auto send_packet_header_res =
        send_header(sock, RenameReq, seq_num, iv, get_iv_len());
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

    int err = 0;
    unsigned char header = mtype_to_uc(RenameReq);
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, &header, sizeof(unsigned char));
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));
    if (err != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // Actual encryption
    // First encrypt 128 bytes for f_old
    unsigned char *ct = new unsigned char[FNAME_MAX_LEN * 2 + get_block_size()];
    if (EVP_EncryptUpdate(ctx, ct, &len, f_old, FNAME_MAX_LEN) != 1) {
        delete[] iv;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len = len;

    // Then encrypt 128 bytes for f_new
    if (EVP_EncryptUpdate(ctx, ct + ct_len, &len, f_new, FNAME_MAX_LEN) != 1) {
        delete[] iv;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len += len;

    // Finalize encryption
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
        EVP_CIPHER_CTX_free(ctx);
        delete[] ct;
        delete[] tag;
        handle_errors(ct_send_res.error);
    }
    delete[] ct;

    auto tag_send_res = send_tag(sock, tag);
    if (tag_send_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] tag;
        handle_errors(tag_send_res.error);
    }
    delete[] tag;

    inc_seqnum();

    //------------------Wait server response------------------

    auto mtype_res = get_mtype(sock);
    if (mtype_res.is_error ||
        (mtype_res.result != RenameAns && mtype_res.result != Error)) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors("Incorrect message type");
    }

    // read iv and sequence number
    auto server_header_res = read_header(sock);
    if (server_header_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    auto [seq, in_iv] = server_header_res.result;
    iv = in_iv;

    // Check correctness of the sequence number
    if (seq != seq_num) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] iv;
        handle_errors("Incorrect sequence number");
    }

    // read ciphertext
    auto ct_res = read_field(sock);
    if (ct_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] iv;
        handle_errors();
    }
    auto ct_tuple = ct_res.result;
    ct_len = get<0>(ct_tuple);
    ct = get<1>(ct_tuple);

    // read tag
    auto tag_res = read_tag(sock);
    if (tag_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] ct;
        delete[] iv;
        handle_errors();
    }
    tag = tag_res.result;

    if (EVP_DecryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    delete[] iv;

    header = mtype_to_uc(mtype_res.result);

    /* Specify authenticated data */
    err = 0;
    err |= EVP_DecryptUpdate(ctx, nullptr, &len, &header, sizeof(mtype));
    err |=
        EVP_DecryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));

    if (err != 1) {
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // Allocate plaintext of the length == ciphertext length
    auto *pt = new unsigned char[ct_len];
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
    }

    // GCM tag check
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

    // Encrypt Final. Finalize the encryption and adds the padding
    if (EVP_DecryptFinal(ctx, pt + len, &len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
    }

    cout << endl << pt << endl;

    // free context
    EVP_CIPHER_CTX_free(ctx);
    delete[] pt;
    delete[] ct;
    delete[] tag;

    inc_seqnum();
}
