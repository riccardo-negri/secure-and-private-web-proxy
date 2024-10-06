/* client-tls.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
#include "client-tls.h"

#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>
#include    <errno.h>
#include    <arpa/inet.h>
#include    <wolfssl/ssl.h>          /* wolfSSL secure read/write methods */
#include    <wolfssl/certs_test.h>

#define MAXDATASIZE  4096           /* maximum acceptable amount of data */
#define SERV_PORT    443          /* define default port number */

int client_connect_untrusted()
{
    int     sgxStatus;

    int     sockfd;                         /* socket file descriptor */
    struct  sockaddr_in servAddr;           /* struct for server address */
    int     ret = 0;                        /* variable for error checking */

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX*    ctx;
    WOLFSSL*        ssl;


    /* data to send to the server, data recieved from the server */
    char    sendBuff[] = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
    char rcvBuff[MAXDATASIZE] = {0};

    /* internet address family, stream based tcp, default protocol */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        printf("Failed to create socket. errno: %i\n", errno);
        return EXIT_FAILURE;
    }

    memset(&servAddr, 0, sizeof(servAddr)); /* clears memory block for use */
    servAddr.sin_family = AF_INET;          /* sets addressfamily to internet*/
    servAddr.sin_port = htons(SERV_PORT);   /* sets port to defined port */

    /* looks for the server at the entered address (ip in the command line) */
    if (inet_pton(AF_INET, "93.184.215.14", &servAddr.sin_addr) < 1) {
    //if (inet_pton(AF_INET, "127.0.0.1", &servAddr.sin_addr) < 1) {    
        /* checks validity of address */
        ret = errno;
        printf("Invalid Address. errno: %i\n", ret);
        return EXIT_FAILURE;
    }

    if (connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
        ret = errno;
        printf("Connect error. Error: %i\n", ret);
        return EXIT_FAILURE;
    }

    //Initialize wolfSSL
    int res = wolfSSL_Debugging_ON();
    if (res != 0) {
        ocall_print_string("Error setting debugging on\n");
        if (res == -174) {
            ocall_print_string("Error code: not compiled in!\n");
        }
    }
    else {
        ocall_print_string("Debugging on\n");
    }

    wolfSSL_Init();

    // Create and setup the SSL context
    method = wolfTLSv1_2_client_method();
    if (method == NULL) {
        printf("wolfTLSv1_2_client_method failure\n");
        return EXIT_FAILURE;
    }

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        printf("wolfSSL_CTX_new failure\n");
        return EXIT_FAILURE;
    }

    // get all available ciphers
    char ciphers22[MAXDATASIZE] = {0};;
    wolfSSL_get_ciphers(ciphers22, MAXDATASIZE);
    printf("Ciphers: %s\n", ciphers22);


    // Set ciphers to exclude elliptic curves
    const char *ciphers = "ALL:!ECDHE:!ECDH:!EC:!ECDSA:!aNULL:!eNULL:!LOW:!EXPORT:!RC4:!MD5:!PSK:!SRP:!DSS";
    if (wolfSSL_CTX_set_cipher_list(ctx, ciphers) != SSL_SUCCESS) {
        printf("Failed to set cipher list\n");
        return EXIT_FAILURE;
    }

    wolfSSL_get_ciphers(ciphers22, MAXDATASIZE);
    printf("Ciphers: %s\n", ciphers22);
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
    const char digiCert_Global_Root_G2_cert[] = "-----BEGIN CERTIFICATE-----\nMIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQG\nEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAw\nHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUx\nMjAwMDBaMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3\ndy5kaWdpY2VydC5jb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI2/Ou8jqJ\nkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx1x7e/dfgy5SDN67sH0NO\n3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQq2EGnI/yuum06ZIya7XzV+hdG82MHauV\nBJVJ8zUtluNJbd134/tJS7SsVQepj5WztCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyM\nUNGPHgm+F6HmIcr9g+UQvIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQAB\no0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV5uNu\n5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY1Yl9PMWLSn/pvtsr\nF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4NeF22d+mQrvHRAiGfzZ0JFrabA0U\nWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NGFdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBH\nQRFXGU7Aj64GxJUTFy8bJZ918rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/\niyK5S9kJRaTepLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl\nMrY=\n-----END CERTIFICATE-----\n";

    ret = wolfSSL_CTX_load_verify_buffer(ctx, digiCert_Global_Root_G2_cert, sizeof(digiCert_Global_Root_G2_cert), SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        printf("wolfSSL_CTX_use_certificate_chain_buffer_format failure. Error: %d\n", ret);
        return;
    }  

    // Create the SSL object
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        printf("wolfSSL_new failure\n");
        return EXIT_FAILURE;
    }
    

    // Associate the socket with the SSL object
    ret = wolfSSL_set_fd(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
        printf("wolfSSL_set_fd failure\n");
        return EXIT_FAILURE;
    }

    printf("--> Before with server <--\n");
    // Perform the SSL/TLS handshake
    ret = wolfSSL_connect(ssl);
    if (ret != SSL_SUCCESS) {
        printf("wolfSSL_connect failure\n");
        return EXIT_FAILURE;
    }

    wolfSSL_get_error(ssl, ret);
    printf("Error: %i\n", ret);
    printf("--> Connected with server <--\n"); 

    // Send data to the server
    ret = wolfSSL_write(ssl, sendBuff, strlen(sendBuff));

    if (ret != strlen(sendBuff)) {
        // the message is not able to send, or error trying
        wolfSSL_get_error(ssl, ret);
        printf("Write error: Error: %i\n", ret);
        return EXIT_FAILURE;
    }

    printf("Sent: \t%s\n", sendBuff);
    fflush(stdout);

    // Receive data from the server
    ret = wolfSSL_read(ssl, rcvBuff, MAXDATASIZE);

    if (ret < 0) {
        // the server failed to send data, or error trying
        wolfSSL_get_error(ssl, ret);
        printf("Read error. Error: %i\n", ret);
        return EXIT_FAILURE;
    }

    printf("Recieved: \t%s\n", rcvBuff);

    return 0;
}