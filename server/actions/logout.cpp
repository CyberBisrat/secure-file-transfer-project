#include "../../common/errors.h"
#include "../../common/seq.h"
#include "../../common/types.h"
#include "../../common/utils.h"
#include <openssl/evp.h>
#include <sys/socket.h>

void logout(int sock, unsigned char *key) {

    // -----------receive client logout request-----------

    auto server_header_res = read_header(sock);
    if (server_header_res.is_error) {
        handle_errors();
    }
    auto [seq, iv] = server_header_res.result;

    if (seq != seq_num) {
        delete[] iv;
        handle_errors("Incorrect sequence number");
    }

    auto ct_res = read_field(sock);
    if (ct_res.is_error) {
        delete[] iv;
        handle_errors("Incorrect message type");
    }
    auto [ct_len, ct] = ct_res.result;

    auto tag_res = read_tag(sock);
    if (tag_res.is_error) {
        delete[] ct;
        delete[] iv;
        handle_errors("Incorrect message type");
    }
    auto tag = tag_res.result;

    EVP_CIPHER_CTX *ctx;
    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        handle_errors("Could not decrypt message (alloc)");
    }
    int len;

    // Decrypt init
    if (EVP_DecryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    delete[] iv;

    unsigned char header = mtype_to_uc(LogoutReq);

    /* Zero or more calls to specify any AAD */
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

    // GCM tag check
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

    // Encrypt Final. Finalize the encryption and adds the padding
    if (EVP_DecryptFinal(ctx, pt + len, &len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
    }

    // free context
    EVP_CIPHER_CTX_reset(ctx);
    delete[] ct;
    delete[] tag;
    delete[] pt;

    seq_num++;

    //---------------------------------------------------------------------------------
    //---------------------------------------------------------------------------------
    //---------------------------------------------------------------------------------

    // Send logout response
    // Generate iv for message
    auto iv_res = gen_iv();
    if (iv_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors(iv_res.error);
    }
    iv = iv_res.result;

    // Send logout request plaintext part
    auto send_packet_header_res =
        send_header(sock, LogoutAns, seq_num, iv, get_iv_len());
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

    err = 0;
    header = mtype_to_uc(LogoutAns);
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, &header, sizeof(unsigned char));
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));
    if (err != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // Get dummy value to encrypt
    auto dummy_res = get_dummy();
    if (dummy_res.is_error) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    auto dummy = dummy_res.result;

    ct = new unsigned char[DUMMY_LEN + get_block_size()];
    if (EVP_EncryptUpdate(ctx, ct, &len, dummy, DUMMY_LEN) != 1) {
        delete[] iv;
        delete[] dummy;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len = len;

    if (EVP_EncryptFinal(ctx, ct + len, &len) != 1) {
        delete[] iv;
        delete[] dummy;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len += len;

    tag = new unsigned char[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) != 1) {
        delete[] iv;
        delete[] dummy;
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    delete[] iv;
    delete[] dummy;
    EVP_CIPHER_CTX_free(ctx);

    auto ct_send_res = send_field(sock, (flen)ct_len, ct);
    if (ct_send_res.is_error) {
        delete[] ct;
        delete[] tag;
        handle_errors(ct_send_res.error);
    }

    auto tag_send_res = send_tag(sock, tag);
    if (tag_send_res.is_error) {
        delete[] ct;
        delete[] tag;
        handle_errors(tag_send_res.error);
    }

    delete[] ct;
    delete[] tag;

    // end of connection
}
