#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define BUFSIZE 2048

int sign_file(const char *input_file, const char *output_file, const char *private_key_file, const char *cert_file) {
    FILE *in_file = fopen(input_file, "rb");
    if (!in_file) {
        perror("Error opening input file");
        return 1;
    }

    FILE *out_file = fopen(output_file, "wb");
    if (!out_file) {
        perror("Error opening output file");
        fclose(in_file);
        return 1;
    }

    EVP_PKEY *private_key = NULL;
    FILE *private_key_fp = fopen(private_key_file, "r");
    if (!private_key_fp) {
        perror("Error opening private key file");
        fclose(in_file);
        fclose(out_file);
        return 1;
    }
    private_key = PEM_read_PrivateKey(private_key_fp, NULL, NULL, NULL);
    fclose(private_key_fp);
    if (!private_key) {
        perror("Error reading private key");
        fclose(in_file);
        fclose(out_file);
        return 1;
    }

    X509 *cert = NULL;
    FILE *cert_fp = fopen(cert_file, "r");
    if (!cert_fp) {
        perror("Error opening certificate file");
        EVP_PKEY_free(private_key);
        fclose(in_file);
        fclose(out_file);
        return 1;
    }
    cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    fclose(cert_fp);
    if (!cert) {
        perror("Error reading certificate");
        EVP_PKEY_free(private_key);
        fclose(in_file);
        fclose(out_file);
        return 1;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        perror("Error creating message digest context");
        X509_free(cert);
        EVP_PKEY_free(private_key);
        fclose(in_file);
        fclose(out_file);
        return 1;
    }

    EVP_PKEY_CTX *pkey_ctx;
    if (!EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha256(), NULL, private_key)) {
        perror("Error initializing digest signing");
        EVP_MD_CTX_free(md_ctx);
        X509_free(cert);
        EVP_PKEY_free(private_key);
        fclose(in_file);
        fclose(out_file);
        return 1;
    }

    unsigned char buf[BUFSIZE];
    int len;
    while ((len = fread(buf, 1, BUFSIZE, in_file)) > 0) {
        if (!EVP_DigestSignUpdate(md_ctx, buf, len)) {
            perror("Error updating digest");
            EVP_MD_CTX_free(md_ctx);
            X509_free(cert);
            EVP_PKEY_free(private_key);
            fclose(in_file);
            fclose(out_file);
            return 1;
        }
    }

    size_t signature_len;
    if (!EVP_DigestSignFinal(md_ctx, NULL, &signature_len)) {
        perror("Error determining signature length");
        EVP_MD_CTX_free(md_ctx);
        X509_free(cert);
        EVP_PKEY_free(private_key);
        fclose(in_file);
        fclose(out_file);
        return 1;
    }

    unsigned char *signature = (unsigned char *)malloc(signature_len);
    if (!signature) {
        perror("Error allocating memory for signature");
        EVP_MD_CTX_free(md_ctx);
        X509_free(cert);
        EVP_PKEY_free(private_key);
        fclose(in_file);
        fclose(out_file);
        return 1;
    }

    if (!EVP_DigestSignFinal(md_ctx, signature, &signature_len)) {
        perror("Error signing digest");
        free(signature);
        EVP_MD_CTX_free(md_ctx);
        X509_free(cert);
        EVP_PKEY_free(private_key);
        fclose(in_file);
        fclose(out_file);
        return 1;
    }

    fwrite(signature, 1, signature_len, out_file);

    free(signature);
    EVP_MD_CTX_free(md_ctx);
    X509_free(cert);
    EVP_PKEY_free(private_key);
    fclose(in_file);
    fclose(out_file);

    return 0;
}

int main() {
    const char *input_file = "network_traffic.txt";
    const char *output_file = "network_traffic_signed.bin";
    const char *private_key_file = "private_key.pem";
    const char *cert_file = "certificate.pem";

    if (sign_file(input_file, output_file, private_key_file, cert_file) != 0) {
        printf("Error signing file\n");
        return 1;
    }

    printf("File signed successfully\n");

    return 0;
}
