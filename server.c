#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <time.h>

#define PORT 9999
#define BUFFER_SIZE 1024
#define TIMEOUT 60 

typedef struct {
    int socket;
    SSL *ssl;
    time_t last_activity;
} connection_t;

connection_t connections[FD_SETSIZE];
pthread_mutex_t connections_mutex = PTHREAD_MUTEX_INITIALIZER;

void handle_client(SSL *ssl) {
    const char *json_message = "{\"status\": \"ok\", \"message\": \"Hello from secure server!\"}";

    SSL_write(ssl, json_message, strlen(json_message));

    //SSL_shutdown(ssl);
    //SSL_free(ssl);
}

void *server_thread(void *arg) {
    SSL_CTX *ctx = (SSL_CTX *)arg;
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 5) < 0) {
        perror("listen");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Secure server with client certificate verification listening on port %d\n", PORT);

    while (1) {
        client_addr_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            perror("accept");
            continue;
        }

        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_socket);
        } else {
            X509 *client_cert = SSL_get_peer_certificate(ssl);
            if (client_cert != NULL) {
                printf("Client certificate:\n");
                X509_print_fp(stdout, client_cert);
                X509_free(client_cert);

                if (SSL_get_verify_result(ssl) == X509_V_OK) {
                   
                    pthread_mutex_lock(&connections_mutex);
                    for (int i = 0; i < FD_SETSIZE; i++) {
                        if (connections[i].socket == 0) {
                            connections[i].socket = client_socket;
                            connections[i].ssl = ssl;
                            connections[i].last_activity = time(NULL);
                            break;
                        }
                    }
                    pthread_mutex_unlock(&connections_mutex);
                    handle_client(ssl);
                } else {
                    printf("Client certificate verification failed.\n");
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    close(client_socket);
                }
            } else {
                printf("No client certificate presented.\n");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_socket);
            }
        }
    }

    close(server_socket);
    return NULL;
}

void *cleanup_thread(void *arg) {
    (void)arg;

    while (1) {
        pthread_mutex_lock(&connections_mutex);
        time_t now = time(NULL);
        for (int i = 0; i < FD_SETSIZE; i++) {
            if (connections[i].socket != 0) {
                if (difftime(now, connections[i].last_activity) > TIMEOUT) {
                    printf("Closing inactive connection on socket %d\n", connections[i].socket);
                    
                    SSL_shutdown(connections[i].ssl);
                    SSL_free(connections[i].ssl);
                    close(connections[i].socket);
                    
                    connections[i].socket = 0;
                    connections[i].ssl = NULL;
                    connections[i].last_activity = 0;
                }
            }
        }
        pthread_mutex_unlock(&connections_mutex);
        sleep(5);
    }

    return NULL;
}

int main() {
    pthread_t server_tid, cleanup_tid;

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);

    if (pthread_create(&server_tid, NULL, server_thread, (void *)ctx) != 0) {
        perror("Failed to create server thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&cleanup_tid, NULL, cleanup_thread, NULL) != 0) {
        perror("Failed to create cleanup thread");
        exit(EXIT_FAILURE);
    }

    pthread_join(server_tid, NULL);
    pthread_join(cleanup_tid, NULL);

    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
