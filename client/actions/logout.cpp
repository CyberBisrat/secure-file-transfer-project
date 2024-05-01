#include "../../common/errors.h"
#include "../../common/seq.h"
#include "../../common/types.h"
#include "../../common/utils.h"
#include <openssl/evp.h>
#include <sys/socket.h>

void logout(int sock, unsigned char *key) {

    // Generate iv for message
    auto iv_res = gen_iv();
    if (iv_res.is_error) {
        handle_errors(iv_res.error);
    }
    auto iv = iv_res.result;

    // Send logout request plaintext part
    auto send_packet_header_res =
        send_header(sock, LogoutReq, seq_num, iv, get_iv_len());
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
    unsigned char header = mtype_to_uc(LogoutReq);
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

    unsigned char *ct = new unsigned char[DUMMY_LEN + get_block_size()];
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

    unsigned char *tag = new unsigned char[TAG_LEN];
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
    EVP_CIPHER_CTX_reset(ctx);

    auto ct_send_res = send_field(sock, (flen)ct_len, ct);
    if (ct_send_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] ct;
        delete[] tag;
        handle_errors(ct_send_res.error);
    }

    auto tag_send_res = send_tag(sock, tag);
    if (tag_send_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] ct;
        delete[] tag;
        handle_errors(tag_send_res.error);
    }
    delete[] ct;
    delete[] tag;

    // Manually increase sequence number without any check, otherwise we may
    // trigger the SIGUSR1 signal again
    seq_num++;

    //------------------------------------------

    // -----------receive client logout request-----------
    auto mtype_res = get_mtype(sock);
    if (mtype_res.is_error || mtype_res.result != LogoutAns) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    auto server_header_res = read_header(sock);
    if (server_header_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    auto [seq, in_iv] = server_header_res.result;
    iv = in_iv;

    if (seq != seq_num) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] iv;
        handle_errors("Incorrect sequence number");
    }

    auto ct_res = read_field(sock);
    if (ct_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] iv;
        handle_errors("Incorrect message type");
    }
    auto ct_tuple = ct_res.result;
    ct_len = get<0>(ct_tuple);
    ct = get<1>(ct_tuple);

    auto tag_res = read_tag(sock);
    if (tag_res.is_error) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] ct;
        delete[] iv;
        handle_errors("Incorrect message type");
    }
    tag = tag_res.result;

    // Decrypt init
    if (EVP_DecryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    delete[] iv;

    header = mtype_to_uc(mtype_res.result);

    /* Zero or more calls to specify any AAD */
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

    auto *pt = new unsigned char[ct_len];
    // Encrypt Update: one call is enough because our message is very short.
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) {
        delete[] ct;
        delete[] pt;
        delete[] tag;
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
    EVP_CIPHER_CTX_free(ctx);
    delete[] ct;
    delete[] tag;
    delete[] pt;

    // END OF COMMUNICATION
}
