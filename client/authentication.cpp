#include "authentication.h"
#include "../common/dhparams.h"
#include "../common/errors.h"
#include "../common/types.h"
#include "../common/utils.h"
#include <iostream>
#include <new>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>
#include <string>
#include <tuple>

using namespace std;

Maybe<EVP_PKEY *> verify_certificate_and_get_key(X509 *cert) {
    Maybe<EVP_PKEY *> res;

    // Allocate store
    X509_STORE *store;
    if ((store = X509_STORE_new()) == nullptr) {
        res.set_error("Could not allocate X509 store");
        return res;
    }

    // Load root certificate
    FILE *root_cert_fp;
    if ((root_cert_fp = fopen("certificates/rootCA.crt", "r")) == nullptr) {
        X509_STORE_free(store);
        res.set_error("Could not open root certificate");
        return res;
    }

    X509 *root_cert;
    if ((root_cert = PEM_read_X509(root_cert_fp, nullptr, nullptr, nullptr)) ==
        nullptr) {
        X509_STORE_free(store);
        fclose(root_cert_fp);
        res.set_error("Could not deserialize PEM root certificate");
        return res;
    }
    fclose(root_cert_fp);

    // Add the root certificate as a trusted certificate to the store
    if (X509_STORE_add_cert(store, root_cert) != 1) {
        X509_STORE_free(store);
        X509_free(root_cert);
        res.set_error("Could not add root certificate to the store");
        return res;
    }

    // Verify the received certificate
    X509_STORE_CTX *ctx;
    if ((ctx = X509_STORE_CTX_new()) == nullptr) {
        X509_STORE_free(store);
        X509_free(root_cert);
        res.set_error("Could not allocate verification context");
        return res;
    }

    int err = 0;
    err |= X509_STORE_CTX_init(ctx, store, cert, nullptr);
    err |= X509_verify_cert(ctx);
    if (err != 1) {
        X509_STORE_free(store);
        X509_free(root_cert);
        X509_STORE_CTX_free(ctx);
        res.set_error("Certificate could not be verified correctly");
        return res;
    }

    X509_STORE_CTX_free(ctx);
    X509_free(root_cert);
    X509_STORE_free(store);

    // Extract public key from validated certificate
    EVP_PKEY *pubkey;
    if ((pubkey = X509_get_pubkey(cert)) == nullptr) {
        res.set_error("Could not retrieve pubkey from certificate");
    } else {
        res.set_result(pubkey);
    }
    return res;
}

unsigned char *authenticate(int socket, int key_len) {
    cout << "Username: ";
    string username;
    getline(cin, username);

    // Check that the length of the name doesn't exceed the maximum length of a
    // packet field
    if (username.length() + 1 > FLEN_MAX) {
        handle_errors("Username is too long");
    }

    // ---------------------------------------------------------------------- //
    // ----------------- Client's opening message to Server ----------------- //
    // ---------------------------------------------------------------------- //

    // Authentication start
    auto send_auth_start_header_res = send_header(socket, AuthStart);
    if (send_auth_start_header_res.is_error) {
        handle_errors("Incorrect header during authentication (AuthStart)");
    }

    // Send the username
    auto send_username_res =
        send_field(socket, username.length() + 1,
                   reinterpret_cast<unsigned char *>(
                       const_cast<char *>(username.c_str())));
    if (send_username_res.is_error) {
        handle_errors(send_username_res.error);
    }

    // Send the client's half key
    auto keypair = gen_keypair();

#ifdef DEBUG
    cout << "Client half key:" << endl;
    PEM_write_PUBKEY(stdout, keypair);
    cout << endl;
#endif

    // Initialize a memory bio
    BIO *tmp_bio;
    if ((tmp_bio = BIO_new(BIO_s_mem())) == nullptr) {
        EVP_PKEY_free(keypair);
        handle_errors("Could not create memory bio");
    }

    // Write the half key as PEM into it
    if (PEM_write_bio_PUBKEY(tmp_bio, keypair) != 1) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        handle_errors("Could not write to memory bio");
    }

    // Get the length and a pointer to the bio's memory data
    long client_half_key_len;
    unsigned char *client_half_key_ptr;
    if ((client_half_key_len =
             BIO_get_mem_data(tmp_bio, &client_half_key_ptr)) <= 0) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        handle_errors("Could not get access to internal memory of memory bio");
    }

    // Check if the size of the public key is less than the maximum size of a
    // packet field
    if (client_half_key_len > FLEN_MAX) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        handle_errors(
            "Client's half key is bigger than the maximum field's length");
    }

    // Copy the half key for later usage (signature computation/verification)
    unsigned char *client_half_key_pem = new unsigned char[client_half_key_len];
    memcpy(client_half_key_pem, client_half_key_ptr, client_half_key_len);

    // Finally send the half key
    auto send_client_half_key_result =
        send_field(socket, (flen)client_half_key_len, client_half_key_ptr);

    if (send_client_half_key_result.is_error) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        handle_errors(send_client_half_key_result.error);
    }
    BIO_reset(tmp_bio);

    // ---------------------------------------------------------------------- //
    // ------------------ Server's response to the Client ------------------- //
    // ---------------------------------------------------------------------- //

    // Receive the packet header
    auto server_header_result = get_mtype(socket);
    if (server_header_result.is_error ||
        server_header_result.result != AuthServerAns) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        handle_errors("Incorrect message type");
    }

    // Get server name
    auto server_name_result = read_field(socket);
    if (server_name_result.is_error) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        handle_errors(server_name_result.error);
    }
    auto [server_name_len, server_name] = server_name_result.result;

    // This check is more of a sanity check than else, as it should serve no
    // purpose from the security point of view
    if (strncmp("server", reinterpret_cast<char *>(server_name),
                server_name_len) != 0) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        handle_errors("Server's name is incorrect");
    }

    // Receive server's pubkey in PEM format
    auto server_half_key_result = read_field(socket);
    if (server_half_key_result.is_error) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        handle_errors(server_half_key_result.error);
    }
    auto [server_half_key_len, server_half_key_pem] =
        server_half_key_result.result;

    // Write it to memory bio
    if (BIO_write(tmp_bio, server_half_key_pem, server_half_key_len) !=
        server_half_key_len) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        handle_errors("Could not write to memory bio");
    }

    // ... and extract it as the client half key
    auto server_half_key = PEM_read_bio_PUBKEY(tmp_bio, nullptr, 0, nullptr);
    if (server_half_key == nullptr) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        handle_errors("Could not read from memory bio");
    }
    BIO_reset(tmp_bio);

#ifdef DEBUG
    cout << "Server half key:" << endl;
    PEM_write_PUBKEY(stdout, server_half_key);
    cout << endl;
#endif

    // Receive server's certificate and verify it
    auto server_certificate_res = read_field(socket);
    if (server_certificate_res.is_error) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_PKEY_free(server_half_key);
        handle_errors(server_certificate_res.error);
    }

    auto [server_certificate_len, server_certificate_pem] =
        server_certificate_res.result;

    // Write it to the BIO as PEM
    if (BIO_write(tmp_bio, server_certificate_pem, server_certificate_len) !=
        server_certificate_len) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_PKEY_free(server_half_key);
        delete[] server_certificate_pem;
        handle_errors("Could not write to memory bio");
    }

    // and extract it as a X509 struct
    X509 *server_certificate;
    if ((server_certificate =
             PEM_read_bio_X509(tmp_bio, nullptr, 0, nullptr)) == nullptr) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_PKEY_free(server_half_key);
        delete[] server_certificate_pem;
        handle_errors("Could not read from memory bio");
    }
    delete[] server_certificate_pem;
    BIO_reset(tmp_bio);

    // Verify and extract the public key of the server from the received
    // certificate
    auto server_pubkey_res = verify_certificate_and_get_key(server_certificate);
    if (server_pubkey_res.is_error) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_PKEY_free(server_half_key);
        X509_free(server_certificate);
        handle_errors(server_pubkey_res.error);
    }

    X509_free(server_certificate);
    auto server_pubkey = server_pubkey_res.result;

    // Receive server's digital signature and verify it
    auto server_signature_res = read_field(socket);
    if (server_signature_res.is_error) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_PKEY_free(server_half_key);
        EVP_PKEY_free(server_pubkey);
        handle_errors(server_signature_res.error);
    }

    auto [server_signature_len, server_signature] = server_signature_res.result;

    // Create and initialize the verification context
    EVP_MD_CTX *signature_ctx;
    if ((signature_ctx = EVP_MD_CTX_new()) == nullptr) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_PKEY_free(server_half_key);
        delete[] server_signature;
        EVP_PKEY_free(server_pubkey);
        handle_errors("Signature verification failed (alloc)");
    }

    EVP_VerifyInit(signature_ctx, get_hash_type());

    int err = 0;
    err |= EVP_VerifyUpdate(signature_ctx, client_half_key_pem,
                            client_half_key_len);
    err |= EVP_VerifyUpdate(signature_ctx, server_half_key_pem,
                            server_half_key_len);
    err |= EVP_VerifyUpdate(signature_ctx, username.c_str(),
                            username.length() + 1);

    if (err != 1) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_PKEY_free(server_half_key);
        delete[] server_signature;
        EVP_MD_CTX_free(signature_ctx);
        EVP_PKEY_free(server_pubkey);
        handle_errors("Signature verification failed (update)");
    }

    // Verify that the signature is correct
    if (EVP_VerifyFinal(signature_ctx, server_signature, server_signature_len,
                        server_pubkey) != 1) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_PKEY_free(server_half_key);
        delete[] server_signature;
        EVP_MD_CTX_free(signature_ctx);
        EVP_PKEY_free(server_pubkey);
        handle_errors("Signature verification failed (final)");
    }

    EVP_PKEY_free(server_pubkey);
    EVP_MD_CTX_reset(signature_ctx);
    delete[] server_signature;

    // Computes shared secret
    EVP_PKEY_CTX *shared_secret_ctx;
    if ((shared_secret_ctx = EVP_PKEY_CTX_new(keypair, nullptr)) == nullptr) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_PKEY_free(server_half_key);
        handle_errors("Shared secret creation failed (alloc)");
    }

    err = 0;
    err |= EVP_PKEY_derive_init(shared_secret_ctx);
    err |= EVP_PKEY_derive_set_peer(shared_secret_ctx, server_half_key);

    // Get the length of the shared secret
    size_t shared_secret_len;
    err |= EVP_PKEY_derive(shared_secret_ctx, NULL, &shared_secret_len);

    // Compute the shared secret
    unsigned char *shared_secret = new unsigned char[shared_secret_len];
    err |=
        EVP_PKEY_derive(shared_secret_ctx, shared_secret, &shared_secret_len);

    if (err != 1) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_PKEY_CTX_free(shared_secret_ctx);
        handle_errors("Shared secret creation failed");
    }
    EVP_PKEY_free(server_half_key);
    EVP_PKEY_CTX_free(shared_secret_ctx);

    // Finally, derive the symmetric key from the shared secret
    auto key_res = kdf(shared_secret, shared_secret_len, key_len);
    if (key_res.is_error) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        handle_errors("Shared secret creation failed");
    }
    auto key = key_res.result;
    // ---------------------------------------------------------------------- //
    // -------------------- Client's response to Server --------------------- //
    // ---------------------------------------------------------------------- //

    // Send packet header
    auto send_last_header_res = send_header(socket, AuthClientAns);
    if (send_last_header_res.is_error) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        handle_errors("Could not send header");
    }

    // Compute the signature

    // Initialize the context
    EVP_SignInit(signature_ctx, get_hash_type());

    err = 0;
    err |=
        EVP_SignUpdate(signature_ctx, server_half_key_pem, server_half_key_len);
    err |=
        EVP_SignUpdate(signature_ctx, client_half_key_pem, client_half_key_len);
    err |= EVP_SignUpdate(signature_ctx, server_name, server_name_len);
    if (err != 1) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_MD_CTX_free(signature_ctx);
        handle_errors("Could not sign correctly (update)");
    }

    // Open the client's private key file
    FILE *client_private_key_fp;
    string client_private_key_path = "certificates/" + username + ".key";
    if ((client_private_key_fp = fopen(client_private_key_path.c_str(), "r")) ==
        nullptr) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_MD_CTX_free(signature_ctx);
        handle_errors("Could not open client's private key");
    }

    // and read the key from it
    EVP_PKEY *client_private_key;
    if ((client_private_key = PEM_read_PrivateKey(
             client_private_key_fp, nullptr, 0, nullptr)) == nullptr) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        EVP_MD_CTX_free(signature_ctx);
        fclose(client_private_key_fp);
        handle_errors("Could not read client's private key");
    }
    fclose(client_private_key_fp);

    // Allocate signature buffer
    unsigned char *client_signature =
        new unsigned char[get_signature_max_length(client_private_key)];
    unsigned int client_signature_len;

    // and compute the signature
    if (EVP_SignFinal(signature_ctx, client_signature, &client_signature_len,
                      client_private_key) != 1) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        delete[] client_half_key_pem;
        delete[] server_name;
        delete[] server_half_key_pem;
        delete[] client_signature;
        EVP_PKEY_free(client_private_key);
        EVP_MD_CTX_free(signature_ctx);
        handle_errors("Could not sign correctly (final)");
    }

    EVP_PKEY_free(client_private_key);
    EVP_MD_CTX_free(signature_ctx);
    delete[] server_half_key_pem;
    delete[] client_half_key_pem;
    delete[] server_name;

    // Check if the size of the signature is less than the maximum size of a
    // packet field
    if (client_signature_len > FLEN_MAX) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        handle_errors(
            "Client signature is bigger than the max packet field length");
    }

    // Send the signature to the server
    auto send_client_signature_res =
        send_field(socket, (flen)client_signature_len, client_signature);
    if (send_client_signature_res.is_error) {
        EVP_PKEY_free(keypair);
        BIO_free(tmp_bio);
        handle_errors(send_client_signature_res.error);
    }

    // Free up memory that is no longer needed
    delete[] client_signature;
    EVP_PKEY_free(keypair);
    BIO_free(tmp_bio);

    return key;
}
