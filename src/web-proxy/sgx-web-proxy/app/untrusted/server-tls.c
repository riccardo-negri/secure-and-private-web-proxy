/* server-tls.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "server-tls.h"

/* the usual suspects */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>

/* wolfSSL */
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

#define DEFAULT_PORT 8080

typedef struct {
    sgx_enclave_id_t id;
    int connd;
} client_args;

WOLFSSL_CTX* ctx;

void* handle_client(void* arg) {
    client_args* args = (client_args*)arg;
    sgx_enclave_id_t id = args->id;
    int connd = args->connd;
    free(args);

    enc_serve_HTTP_Request(id, connd, ctx);

    close(connd);
    return NULL;
}

int server_connect(sgx_enclave_id_t id) {
    /* wolfSSL objects */
    int sgxStatus;
    WOLFSSL_METHOD* method;

    /* Initialize wolfSSL */
    enc_wolfSSL_Init(id, &sgxStatus);
    
    /* Create and initialize WOLFSSL_CTX */
    sgxStatus = enc_wolfTLSv1_2_server_method(id, &method);
    if (sgxStatus != SGX_SUCCESS || method == NULL) {
        printf("wolfTLSv1_2_server_method failure\n");
        return EXIT_FAILURE;
    }

    sgxStatus = enc_wolfSSL_CTX_new(id, &ctx, method);
    if (sgxStatus != SGX_SUCCESS || ctx == NULL) {
        printf("wolfSSL_CTX_new failure\n");
        return EXIT_FAILURE;
    }

    enc_create_key_and_x509(id, ctx);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Failed to create the socket");
        return -1;
    }

    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) == -1) {
        perror("Failed to set socket options");
        return -1;
    }

    struct sockaddr_in servAddr = {0};
    servAddr.sin_family      = AF_INET;
    servAddr.sin_port        = htons(DEFAULT_PORT);
    servAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
        perror("Failed to bind the socket");
        return -1;
    }

    if (listen(sockfd, 10) == -1) {
        perror("Failed to listen on socket");
        return -1;
    }

    printf("Waiting for a connection...\n");

    while (1) {
        struct sockaddr_in clientAddr;
        socklen_t size = sizeof(clientAddr);
        int connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size);
        if (connd == -1) {
            perror("Failed to accept the connection");
            return -1;
        }

        client_args* args = malloc(sizeof(client_args));
        args->id = id;
        args->connd = connd;
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, args) != 0) {
            perror("Failed to create thread");
            free(args);
            continue;
        }

        pthread_detach(thread);
    }
    
    return 0;
}
 