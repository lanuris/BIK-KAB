#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#define HOST "fit.cvut.cz"
#define PORT 443
#define URL "GET /cs/fakulta/o-fakulte HTTP/1.1\r\nHost: " HOST "\r\nConnection: close\r\n\r\n"


void initOpenssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *createContext() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ctx);

    return ctx;
}

// void resolveHostnameIPv4v6(const char* hostname) {
//     struct addrinfo hints, *result, *rp;
//     int status;

//     // Clear the hints structure
//     memset(&hints, 0, sizeof(struct addrinfo));
//     hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
//     hints.ai_socktype = SOCK_STREAM; // Use TCP

//     // Call getaddrinfo to resolve the hostname
//     status = getaddrinfo(hostname, NULL, &hints, &result);
//     if (status != 0) {
//         perror("Unable to translate adress");
//         exit(EXIT_FAILURE);
//     }
// for (rp = result; rp != NULL; rp = rp->ai_next) {
//         void* addr;
//         char ipstr[INET6_ADDRSTRLEN];

//         if (rp->ai_family == AF_INET) { // IPv4
//             struct sockaddr_in* ipv4 = (struct sockaddr_in*)rp->ai_addr;
//             addr = &(ipv4->sin_addr);
//         } else { // IPv6
//             struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)rp->ai_addr;
//             addr = &(ipv6->sin6_addr);
//         }

//         // Convert the IP address to a human-readable string
//         inet_ntop(rp->ai_family, addr, ipstr, sizeof(ipstr));
//         printf("Resolved address: %s\n", ipstr);
//     }

//     // Free the linked list returned by getaddrinfo
//     freeaddrinfo(result);
// }

struct addrinfo * resolveHostnameIPv4(const char* hostname) {
    struct addrinfo hints, *result;
    int status;

    // Clear the hints structure
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; // Allow IPv4 
    hints.ai_socktype = SOCK_STREAM; // Use TCP

    // Call getaddrinfo to resolve the hostname
    status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0) {
        perror("Unable to translate adress");
        exit(EXIT_FAILURE);
        return NULL;
    }

    void* addr;
    char ipstr[INET_ADDRSTRLEN];

    struct sockaddr_in* ipv4 = (struct sockaddr_in*)result->ai_addr;
    addr = &(ipv4->sin_addr);

    // Convert the IP address to a human-readable string
    inet_ntop(result->ai_family, addr, ipstr, sizeof(ipstr));
    printf("Resolved address: %s\n", ipstr);

    return result;
}    

int createSocket(struct addrinfo *result) {
    int sock;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);

    struct sockaddr_in* ipv4 = (struct sockaddr_in*)result->ai_addr;
    addr.sin_addr.s_addr = ipv4->sin_addr.s_addr;
    //addr.sin_addr.s_addr = inet_addr("147.32.232.212");

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Connect failed");
        exit(EXIT_FAILURE);
    }

    return sock;
}

void showCertInfo(SSL *ssl) {
    X509 *cert;
    char *line;
    long sslVerifyResult = SSL_get_verify_result(ssl);

    
    if (sslVerifyResult != X509_V_OK) {
        printf("Certifikát serveru nebyl ověřen. Chybový kód: %ld\n", sslVerifyResult);
        exit(EXIT_FAILURE);
    }    
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Certifikát serveru byl úspěšně ověřen.\n");
        printf("Server certificates:\n");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);

        FILE *fp = fopen("server_cert.pem", "w");
        PEM_write_X509(fp, cert);
        fclose(fp);

        X509_free(cert);
    } else {
        printf("No certificates.\n");
    }
}

void changeCipher(SSL *ssl) {

    const char *original_cipher = SSL_get_cipher_name(ssl);
    printf("Original cipher: %s\n", original_cipher);

    // Change cipher suite here if needed
    // SSL_set_cipher_list(ssl, "DEFAULT:!SEED");
    const char *new_cipher = "TLS_AES_128_GCM_SHA256";
    printf("New cipher after restriction: %s\n", new_cipher);
}

int main() {

    int sock;
    SSL_CTX *ctx;
    SSL *ssl;
    struct addrinfo *result;

    //0 prelozim adresu
    result = resolveHostnameIPv4(HOST);

    //1 Vytvořte TCP spojení na server fit.cvut.cz, port 443 (viz socket, connect) 
    sock = createSocket(result);

    //2 Inicializujte knihovnu OpenSSL (SSL_library_init)
    initOpenssl();

    //3 Vytvořte nový kontext (SSL_CTX_new, použijte metodu TLS_client_method (Zakažte zastaralé a děravé protokoly)
    ctx = createContext();

    //4 Vytvořte SSL strukturu (SSL_new)
    ssl = SSL_new(ctx);

    //5 Přiřaďte otevřené spojení (SSL_set_fd)
    SSL_set_fd(ssl, sock);

    //6 Nastavte jméno požadovaného serveru pro mechanizmus SNI: (SSL_set_tlsext_host_name)
    SSL_set_tlsext_host_name(ssl, HOST);

    //7 Zahajte SSL komunikaci (SSL_connect)
    if (SSL_connect(ssl) == 1) {


        printf("SSL connection using %s\n", SSL_get_cipher(ssl));

        showCertInfo(ssl);
        // changeCipher(ssl);

        if (SSL_write(ssl, URL, strlen(URL)) == 0){
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
       
        char buf[1024];
        int bytes;
        FILE *fp = fopen("output.html", "w");

        while ((bytes = SSL_read(ssl, buf, sizeof(buf) - 1)) > 0) {
            fwrite(buf, 1, bytes, fp);
        }

        fclose(fp);

    } else {
        ERR_print_errors_fp(stderr);
    }

    //9 Na závěr po sobě uklidíme
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    freeaddrinfo(result);
    return 0;
}