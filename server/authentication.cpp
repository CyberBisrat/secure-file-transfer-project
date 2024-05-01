#include "authentication.h"
#include "../common/dhparams.h"
#include "../common/errors.h"
#include "../common/utils.h"
#include <iostream>
#include <map>
#include <new>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <tuple>

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

void free_user_keys(map<string, EVP_PKEY *> keys) {
    for (auto it = keys.begin(); it != keys.end(); it++) {
        EVP_PKEY_free(it->second);
    }
    keys.clear();
}

// Possible users of the server
string users[2] = {"alice", "bob"};
unsigned char server_name[] = "server";

/* Reads all the public keys of the registered users */
static map<string, EVP_PKEY *> setup_keys() {
    auto user_map = map<string, EVP_PKEY *>();
    FILE *public_key_fp;
    EVP_PKEY *pubkey;

    for (string user : users) {

        // Get the user public key path
        auto user_key_path =
            (fs::canonical(".") / "certificates" / (user + ".pub")).string();

        // Open the public key file
        if ((public_key_fp = fopen(user_key_path.c_str(), "r")) == nullptr) {
            user_map.clear();
            handle_errors();
        }

        // ... and read it as a public key
        if ((pubkey = PEM_read_PUBKEY(public_key_fp, nullptr, 0, nullptr)) ==
            nullptr) {
            fclose(public_key_fp);
            free_user_keys(user_map);
            handle_errors();
        }

        fclose(public_key_fp);

        // ... and save it into the list of users
        user_map.insert({user, pubkey});

#ifdef DEBUG
        cout << "Loaded public key for " << user << endl
             << "Path: " << user_key_path << endl
             << endl;
#endif
    }

    return user_map;
}

/*
 * Runs the key agreement protocol with the client.
 * Returns a tuple containing the username of the client and the agreed key.
 * The caller of this function has to free the memory allocated for the key when
 * done with it.
 */
tuple<char *, unsigned char *> authenticate(int socket, int key_len) {
    // Setup simple associations of usernames and public keys
    auto user_keys = setup_keys();

    // ---------------------------------------------------------------------- //
    // ----------------- Client's opening message to Server ----------------- //
    // ---------------------------------------------------------------------- //

    // Receive first client message
    auto client_header_result = get_mtype(socket);

    // Check the correctness of the message type
    if (client_header_result.is_error ||
        client_header_result.result != AuthStart) {
        free_user_keys(user_keys);
        handle_errors("Incorrect message type");
    }

    // Read the username of the client
    auto username_result = read_field(socket);
    if (username_result.is_error) {
        free_user_keys(user_keys);
        handle_errors(username_result.error);
    }
    auto [username_len, username] = username_result.result;
    username[username_len - 1] = '\0';

#ifdef DEBUG
    cout << endl << "Username length: " << username_len << endl;
    cout << "Username: " << username << endl << endl;
#endif

    // Check that it is registered on the server
    auto finder = user_keys.find(reinterpret_cast<char *>(username));
    EVP_PKEY *client_pubkey = nullptr;
    if (finder != user_keys.end()) {
        client_pubkey = finder->second;
    } else {
        free_user_keys(user_keys);
        delete[] username;
        handle_errors("User not registered!");
    }

    // Load the client's half key
    BIO *tmp_bio;
    if ((tmp_bio = BIO_new(BIO_s_mem())) == nullptr) {
        free_user_keys(user_keys);
        delete[] username;
        handle_errors("Could not allocate memory bio");
    }

    // Read client half key in PEM format
    auto half_key_result = read_field(socket);
    if (half_key_result.is_error) {
        free_user_keys(user_keys);
        delete[] username;
        BIO_free(tmp_bio);
        handle_errors(half_key_result.error);
    }
    auto [client_half_key_len, client_half_key_pem] = half_key_result.result;

    // Write it to memory bio
    if (BIO_write(tmp_bio, client_half_key_pem, client_half_key_len) !=
        client_half_key_len) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        BIO_free(tmp_bio);
        handle_errors("Could not write to memory bio");
    }

    // ... and extract it as the client half key
    auto client_half_key = PEM_read_bio_PUBKEY(tmp_bio, nullptr, 0, nullptr);
    if (client_half_key == nullptr) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        BIO_free(tmp_bio);
        handle_errors("Could not read from memory bio");
    }
    BIO_reset(tmp_bio);

#ifdef DEBUG
    cout << "Client half key:" << endl;
    PEM_write_PUBKEY(stdout, client_half_key);
    cout << endl;
#endif

    // ---------------------------------------------------------------------- //
    // --------------------- Server's response to client -------------------- //
    // ---------------------------------------------------------------------- //

    // Send header
    auto send_header_result = send_header(socket, AuthServerAns);
    if (send_header_result.is_error) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        EVP_PKEY_free(client_half_key);
        handle_errors(send_header_result.error);
    }

    // Send server name ("server")
    auto send_server_name_res =
        send_field(socket, sizeof(server_name), server_name);
    if (send_server_name_res.is_error) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        EVP_PKEY_free(client_half_key);
        handle_errors(send_server_name_res.error);
    }

    // Send server's half key

    // Generate the keypair for the server and write it the public key to the
    // memory bio to extract it as PEM
    auto keypair = gen_keypair();
    if (PEM_write_bio_PUBKEY(tmp_bio, keypair) != 1) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        BIO_free(tmp_bio);
        EVP_PKEY_free(client_half_key);
        handle_errors("Could not write to memory bio");
    };

    // Get the length and a pointer to the bio's memory data
    long server_half_key_len;
    unsigned char *server_half_key_ptr;
    if ((server_half_key_len =
             BIO_get_mem_data(tmp_bio, &server_half_key_ptr)) <= 0) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        BIO_free(tmp_bio);
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors("Could not read from memory bio");
    }

#ifdef DEBUG
    cout << "Server half key:" << endl;
    PEM_write_PUBKEY(stdout, client_half_key);
    cout << endl;
#endif

    // Check if the size of the public key is less than the maximum size of a
    // packet field
    if (server_half_key_len > FLEN_MAX) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        BIO_free(tmp_bio);
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors("Server's half key length is bigger than the maximum "
                      "field's length");
    }

    // Copy the half key for later usage (signature computation/verification)
    unsigned char *server_half_key_pem = new unsigned char[server_half_key_len];
    memcpy(server_half_key_pem, server_half_key_ptr, server_half_key_len);

    // Actually send the half key
    auto send_server_half_key_result =
        send_field(socket, (flen)server_half_key_len, server_half_key_ptr);

    // and check the result
    if (send_server_half_key_result.is_error) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        BIO_free(tmp_bio);
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors(send_server_half_key_result.error);
    }
    BIO_reset(tmp_bio);

    // Send server's certificate

    // Open the certificate file
    FILE *server_certificate_fp;
    if ((server_certificate_fp = fopen("certificates/server.crt", "r")) ==
        nullptr) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        BIO_free(tmp_bio);
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors("Could not open server's certificate file");
    }

    // Read the certificate into an X509 struct
    X509 *server_certificate;
    if ((server_certificate = PEM_read_X509(server_certificate_fp, nullptr, 0,
                                            nullptr)) == nullptr) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        BIO_free(tmp_bio);
        EVP_PKEY_free(client_half_key);
        fclose(server_certificate_fp);
        EVP_PKEY_free(keypair);
        handle_errors("Could not read X509 certificate from file");
    }

    fclose(server_certificate_fp);

    // Save the X509 certificate as PEM and writes it to the memory bio
    if (PEM_write_bio_X509(tmp_bio, server_certificate) != 1) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        BIO_free(tmp_bio);
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        X509_free(server_certificate);
        handle_errors("Could not write to memory bio");
    }

    X509_free(server_certificate);

    // Get the length and a pointer to the bio's memory data
    long server_certificate_len;
    unsigned char *server_certificate_ptr;
    if ((server_certificate_len =
             BIO_get_mem_data(tmp_bio, &server_certificate_ptr)) <= 0) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        BIO_free(tmp_bio);
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors("Could not read from memory bio");
    }

    // Check if the size of the certificate is less than the maximum size of a
    // packet field
    if (server_certificate_len > FLEN_MAX) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        BIO_free(tmp_bio);
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors("Server's certificate length is bigger than the maximum "
                      "field's length");
    }

    // Actually send the certificate
    auto send_server_certificate_result = send_field(
        socket, (flen)server_certificate_len, server_certificate_ptr);

    // and check the result
    if (send_server_certificate_result.is_error) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        BIO_free(tmp_bio);
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors(send_server_certificate_result.error);
    }
    BIO_free(tmp_bio);

    // Sign {g^x, g^y, C} with server's private key and send it

    // Init the signing context
    EVP_MD_CTX *server_signature_ctx;
    if ((server_signature_ctx = EVP_MD_CTX_new()) == nullptr) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors("Could not allocate signing context");
    }
    EVP_SignInit(server_signature_ctx, get_hash_type());

    // Update the context with the data that has to be signed
    int err = 0;
    err |= EVP_SignUpdate(server_signature_ctx, client_half_key_pem,
                          client_half_key_len);
    err |= EVP_SignUpdate(server_signature_ctx, server_half_key_pem,
                          server_half_key_len);
    err |= EVP_SignUpdate(server_signature_ctx, username, username_len);

    if (err != 1) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        EVP_PKEY_free(client_half_key);
        EVP_MD_CTX_free(server_signature_ctx);
        EVP_PKEY_free(keypair);
        handle_errors("Could not sign correctly (update)");
    }

    // Open the server's private key file
    FILE *server_private_key_fp;
    if ((server_private_key_fp = fopen("certificates/server.key", "r")) ==
        nullptr) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        EVP_PKEY_free(client_half_key);
        EVP_MD_CTX_free(server_signature_ctx);
        EVP_PKEY_free(keypair);
        handle_errors("Could not open server's private key");
    }

    // And read the key from it
    EVP_PKEY *server_private_key;
    if ((server_private_key = PEM_read_PrivateKey(
             server_private_key_fp, nullptr, 0, nullptr)) == nullptr) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        EVP_PKEY_free(client_half_key);
        EVP_MD_CTX_free(server_signature_ctx);
        fclose(server_private_key_fp);
        EVP_PKEY_free(keypair);
        handle_errors("Could not read server's private key");
    }
    fclose(server_private_key_fp);

    unsigned char *server_signature =
        new unsigned char[get_signature_max_length(server_private_key)];
    unsigned int server_signature_len;

    if (EVP_SignFinal(server_signature_ctx, server_signature,
                      &server_signature_len, server_private_key) != 1) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        delete[] server_signature;
        EVP_PKEY_free(client_half_key);
        EVP_MD_CTX_free(server_signature_ctx);
        EVP_PKEY_free(keypair);
        EVP_PKEY_free(server_private_key);
        handle_errors("Could not sign correctly (final)");
    }

    EVP_PKEY_free(server_private_key);
    EVP_MD_CTX_free(server_signature_ctx);

    if (server_signature_len > FLEN_MAX) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        delete[] server_signature;
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors(
            "Server signature is bigger than the max packet field length");
    }

    auto send_server_signature_result =
        send_field(socket, (flen)server_signature_len, server_signature);
    if (send_server_signature_result.is_error) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        delete[] server_signature;
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors(send_server_signature_result.error);
    }

    delete[] server_signature;

    // ---------------------------------------------------------------------- //
    // -------------------- Client's response to Server --------------------- //
    // ---------------------------------------------------------------------- //

    // Receive client header
    auto client_header_res = get_mtype(socket);
    if (client_header_res.is_error ||
        client_header_res.result != AuthClientAns) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors(client_header_res.error);
    }

    // Receive client signature and check it
    auto client_signature_res = read_field(socket);
    if (client_signature_res.is_error) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors(client_signature_res.error);
    }

    auto [client_signature_len, client_signature] = client_signature_res.result;

    // Create and initialize the verification context
    EVP_MD_CTX *client_signature_ctx;
    if ((client_signature_ctx = EVP_MD_CTX_new()) == nullptr) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_signature;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_free(keypair);
        handle_errors("Signature verification failed (alloc)");
    }

    EVP_VerifyInit(client_signature_ctx, get_hash_type());

    err = 0;
    err |= EVP_VerifyUpdate(client_signature_ctx, server_half_key_pem,
                            server_half_key_len);
    err |= EVP_VerifyUpdate(client_signature_ctx, client_half_key_pem,
                            client_half_key_len);
    err |= EVP_VerifyUpdate(client_signature_ctx, server_name,
                            sizeof(server_name));

    if (err != 1) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_signature;
        delete[] client_half_key_pem;
        delete[] server_half_key_pem;
        EVP_PKEY_free(client_half_key);
        EVP_MD_CTX_free(client_signature_ctx);
        EVP_PKEY_free(keypair);
        handle_errors("Signature verification failed (update)");
    }

    // Verify that the signature is correct
    if (EVP_VerifyFinal(client_signature_ctx, client_signature,
                        client_signature_len, client_pubkey) != 1) {
        free_user_keys(user_keys);
        delete[] username;
        delete[] client_signature;
        EVP_PKEY_free(client_half_key);
        EVP_MD_CTX_free(client_signature_ctx);
        EVP_PKEY_free(keypair);
        handle_errors("Signature verification failed (final)");
    }

    delete[] client_half_key_pem;
    delete[] server_half_key_pem;
    EVP_MD_CTX_free(client_signature_ctx);
    delete[] client_signature;

    // Computes shared secret
    EVP_PKEY_CTX *shared_secret_ctx;
    if ((shared_secret_ctx = EVP_PKEY_CTX_new(keypair, nullptr)) == nullptr) {
        free_user_keys(user_keys);
        delete[] username;
        EVP_PKEY_free(client_half_key);
        handle_errors("Shared secret creation failed (alloc)");
    }

    err = 0;
    err |= EVP_PKEY_derive_init(shared_secret_ctx);
    err |= EVP_PKEY_derive_set_peer(shared_secret_ctx, client_half_key);

    // Get the length of the shared secret
    size_t shared_secret_len;
    err |= EVP_PKEY_derive(shared_secret_ctx, NULL, &shared_secret_len);

    // Compute the shared secret
    unsigned char *shared_secret = new unsigned char[shared_secret_len];
    err |=
        EVP_PKEY_derive(shared_secret_ctx, shared_secret, &shared_secret_len);

    if (err != 1) {
        free_user_keys(user_keys);
        delete[] username;
        EVP_PKEY_free(client_half_key);
        EVP_PKEY_CTX_free(shared_secret_ctx);
        handle_errors("Shared secret creation failed");
    }

    free_user_keys(user_keys);
    EVP_PKEY_free(keypair);
    EVP_PKEY_free(client_half_key);
    EVP_PKEY_CTX_free(shared_secret_ctx);

    // Finally, derive the symmetric key from the shared secret
    auto key_res = kdf(shared_secret, shared_secret_len, key_len);
    if (key_res.is_error) {
        free_user_keys(user_keys);
        delete[] username;
        handle_errors("Shared secret creation failed");
    }

    auto key = key_res.result;

    return {reinterpret_cast<char *>(username), key};
}
