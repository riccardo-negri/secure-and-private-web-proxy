/* App.c
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
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
*/


#include "stdafx.h"
#include "App.h" /* contains include of Enclave_u.h which has wolfSSL header files */
#include "client-tls.h"
#include "server-tls.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h> // Include this header for DNS resolution

/* Use Debug SGX ? */
#if _DEBUG
	#define DEBUG_VALUE SGX_DEBUG_FLAG
#else
	#define DEBUG_VALUE 1
#endif

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

int main(int argc, char* argv[]) /* not using since just testing w/ wc_test */
{
	sgx_enclave_id_t id;
	sgx_launch_token_t t;

	int ret = 0;
	int sgxStatus = 0;
	int updated = 0;
    func_args args = { 0 };

	/* only print off if no command line arguments were passed in */
	if (argc != 2 || strlen(argv[1]) != 2) {
		printf( 
                "Usage:\n"
                "\t-s Run web proxy in enclave\n"
                "\t-u Run a TLS client in untrusted world\n"
               );
        return 0;
	}

    memset(t, 0, sizeof(sgx_launch_token_t));
    memset(&args,0,sizeof(args));

	ret = sgx_create_enclave(ENCLAVE_FILENAME, DEBUG_VALUE, &t, &updated, &id, NULL);
	if (ret != SGX_SUCCESS) {
		printf("Failed to create Enclave : error %d - %#x.\n", ret, ret);
		return 1;
	}


    switch(argv[1][1]) {
        case 's':
            printf("Web Proxy:\n");
            server_connect(id);
            break;
        case 'u':
            printf("Client Test in Untrusted World:\n");
            client_connect_untrusted();
            break;
        default:
            printf("Unrecognized option set!\n");
            break;
    }

    return 0;
}

void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */ 
    printf("%s", str);
    fflush(stdout);
}

void ocall_low_res_time(int* time)
{
    struct timeval tv;
    if(!time) return;
    *time = tv.tv_sec;
    return;
}

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
    return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
    return send(sockfd, buf, len, flags);
}

void ocall_getipfromdomain(const char* name, char* output, int len) {
    printf("ocall_gethostbyname\n");
    struct hostent *he;
    struct in_addr **addr_list;
    char * ip;
    if ((he = gethostbyname(name)) == NULL) {
        printf("gethostbyname failed\n");
    }
    addr_list = (struct in_addr **) he->h_addr_list;
    // take the first one
    ip = inet_ntoa(*addr_list[0]);
    printf("IP: %s\n", ip);
    
    // write IP in output buffer
    sprintf(output, ip); 
}

int ocall_open_socket_and_connect(const char* ip, int port, int* sockfd) {
    printf("ocall_open_socket_and_connect\n");
    struct sockaddr_in serv_addr;
    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*sockfd < 0) {
        printf("Error opening socket\n");
        return -1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    int conn = connect(*sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    printf("Connected: %d\n", conn);
    return conn;
}