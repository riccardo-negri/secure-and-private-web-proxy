#include <assert.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <stdbool.h>

#include "Enclave_t.h"

#include "sgx_trts.h"
#include "utils.c"

#define RECV_BUFF_SIZE 4096 
#define ENCLAVE_DOMAIN "localhost"
#define ENCLAVE_PORT 8080

/**
 * Look for a domain in a url.
 * Returns the length of the domain if found, 0 otherwise.
 * The pointer to the start of the domain is stored in start_pointer.
*/
int extract_domain_if_present(char * url, int url_len, char ** start_pointer) {
    char * start = strstr(url, "://");
    if (start == NULL) {
        return 0;
    }
    start += 3;
    // find the end of the domain by looking at all the well know suffix like .com, .org, .net, etc.
    
    // array of domain suffixes
    const char *suffixes[] = {".com", ".ch", ".org", ".net", ".edu", ".gov", ".dev"};
    int num_suffixes = 7;

    // find the end of the domain by looking at all the well known suffixes
    for (int i = 0; i < num_suffixes; i++) {
        char * end = strstr(start, suffixes[i]);
        if (end != NULL && end < url + url_len) {
            end += strlen(suffixes[i]);  // move the pointer to the character after the suffix
            if (*end == '/' || *end == '\0') {  // check if the domain ends at this point
                *start_pointer = start;  // set the pointer to the start of the domain
                return end - start;  // return the length of the domain
            }
        }
    }

    return 0;
}

/**
 * Replace URLs in the curr_chunk with the following pattern:
 * <calling_domain>.<enclave_domain>:<port>/?url=<full-url>
 * If a URL does not end in current chunk, the next chunk will be used to find the continuation.
 * Returns the size of the output buffer.
*/
int rewrite_urls(const char * curr_chunk, const int curr_size, const char * next_chunk, const int next_size, const char * enclave_domain, const int port, const char * originating_domain, char * output_buffer) {
    // cycle through current chunk and rewrite all the urls following this pattern:
    // <domain>.localhost:<port>/?url=<full-url>
    const char * inital_output_buffer = output_buffer;
    const char *tags[] = {"href=\"", "src=\"", "location: ", "Location: ", "data-src=\""}; // check if it collides with the logic to check of split tags between chunks
    const char *closing_tags[] = {"\"", "\"", "\n", "\n", "\""};
    const int tags_size = 5;
    char full_url[RECV_BUFF_SIZE*2];

    int slider = 0;
    while (slider < curr_size) {
        // printf("[DEBUG_REWRITING] Slider: %d\n", slider);
        // printf("[DEBUG_REWRITING] Working with chunk: %.*s\n", curr_size, curr_chunk+slider);
        
        // find closest occurrence of one of the above tags
        char * tag_start;
        char * url_start;
        bool url_start_in_next_chunk = false;
        int tag_id = -1;
        for (int i = 0; i < tags_size; i++) {
            char * tag_start_tmp = strstr(curr_chunk + slider, tags[i]);
            char * tag_end_tmp = NULL;

            if (tag_start_tmp >= curr_chunk+curr_size) {
                continue;
            }
            if (tag_start_tmp != NULL) {
                tag_end_tmp = strstr(tag_start_tmp, closing_tags[i]);
            }
            
            // last check is done to make sure that the tag is not empty
            if (tag_start_tmp != NULL && (tag_id == -1 || tag_start_tmp < tag_start) && (tag_end_tmp > tag_start_tmp+1 || tag_end_tmp == NULL)) {
                tag_id = i;
                tag_start = tag_start_tmp;
                // printf("[DEBUG_REWRITING] Found (maybe better) tag: %s\n", tags[i]);
                // find the start of the url: could be after the tag or at the start of next chunk
                url_start = tag_start + strlen(tags[i]);
                if (url_start >= curr_chunk + curr_size) {
                    // the url is in the next chunk
                    url_start = next_chunk;
                    url_start_in_next_chunk = true;
                    // printf("[DEBUG_REWRITING] url start is in next chunk\n");
                }
            }
        }
        if (tag_id == -1) {
            // check manually for split tags definitions between chunks
            // it should not happen because most frameworks align the chunks with the HTML structure
            // like 'hr' in one chunk and 'ef="' in the next
            // printf("[DEBUG_REWRITING] Looking for splitted tags\n");
            for (int i = 0; i < tags_size; i++) {
                // check all different ways the tag could split: 
                // from only 1 char in next chunck, to only 1 char in first chunk
                const char * curr_tag = tags[i];
                const char * curr_tag_len = strlen(curr_tag);
                bool found = false;
                for (int chars_in_first = 1; chars_in_first < curr_tag_len - 1; chars_in_first++) {
                    bool valid = true;
                    // curr (and everything that comes before) is at the end of the first chunk
                    for (int j = 0; j < chars_in_first; j++) {
                        if (curr_chunk[curr_size - chars_in_first + j] != curr_tag[j]) {
                            valid = false;
                            break;
                        }
                    }
                    if (!valid) break;
                    // everything that comes after curr is at the start of next chunk
                    int chars_in_next = curr_tag_len - chars_in_first;
                    for (int j = 0; j < chars_in_next; j++) {
                        if (next_chunk[j] != curr_tag[chars_in_first + j]) {
                            valid = false;
                            break;
                        }
                    }

                    if (valid) {
                        tag_id = i;
                        tag_start = curr_chunk + curr_size - chars_in_first;
                        url_start = next_chunk + chars_in_next;
                        url_start_in_next_chunk = true;
                        found = true;
                        // printf("[DEBUG_REWRITING] Found splitted tag: %s\n", tags[i]);
                        break;
                    }
                }
                if (found) break;
            }
        }

        if (tag_id == -1) {
            // no more tags found
            // copy the rest of the buffer and return
            // printf("[DEBUG_REWRITING] No more tags found, finishing up\n");
            mymemcpy(output_buffer, curr_chunk + slider, curr_size - slider, "debug0");
            output_buffer += curr_size - slider;
            slider = curr_size;
        } 
        else {
            // printf("[DEBUG_REWRITING] Working with tag %s and closing %s\n", tags[tag_id], closing_tags[tag_id]);
            // copy the part of the buffer before the tag
            int min = tag_start - curr_chunk;
            mymemcpy(output_buffer, curr_chunk + slider, min - slider, "debug1");
            output_buffer += min - slider;
            slider = min;        

            // find the end of the url and copy it inside full_url
            // it could be in curr chunk or in next chunk
            char * url_end = strstr(url_start, closing_tags[tag_id]);
            int url_size;
            if (url_start_in_next_chunk || url_end == NULL) {
                // look for the end in the next chunk
                if (url_start_in_next_chunk) {
                    url_end = strstr(url_start, closing_tags[tag_id]);
                }
                else {
                    url_end = strstr(next_chunk, closing_tags[tag_id]);
                }
                
                // printf("[DEBUG_REWRITING] Looking for url end in next chunk\n");
                
                // no end found in next chunk --> we just finish to copy the curr chunk as is
                if (url_end == NULL) {
                    // printf("[WARNING] [DEBUG_REWRITING] No closing quote found in next chunk\n");
                    // copy everything in output from curr chunk and exit
                    mymemcpy(output_buffer, tag_start, curr_size - slider, "debug2");
                    output_buffer += curr_size - slider;
                    return output_buffer - inital_output_buffer;
                }
                else {
                    if (url_start_in_next_chunk) {
                        // url is fully in the next chunk
                        mymemcpy(full_url, url_start, url_end - url_start, "debug3");
                        url_size = url_end - url_start;
                    }
                    else {
                        // url is split between the two chunks
                        // copy the part of the url in the current chunk
                        mymemcpy(full_url, url_start, curr_size - (url_start - curr_chunk), "debug4");
                        url_size = curr_size - (url_start - curr_chunk);                 
                        
                        // copy the rest of the url in the next chunk
                        mymemcpy(full_url + url_size, next_chunk, url_end - next_chunk, "debug5");
                        url_size += url_end - next_chunk;
                    } 
                }
            } 
            else {
                // copy the url
                mymemcpy(full_url, url_start, url_end - url_start, "debug6");
                url_size = url_end - url_start;
            }
            // printf("[DEBUG_REWRITING] Found url: %.*s\n", url_size, full_url);

            // copy the tag
            mymemcpy(output_buffer, tags[tag_id], strlen(tags[tag_id]), "debug7");
            output_buffer += strlen(tags[tag_id]);
            slider += strlen(tags[tag_id]);

            // replace the url
            char * domain;
            int domain_size = extract_domain_if_present(full_url, url_size, &domain);
            int new_url_size;
            if (domain_size == 0) {
                // no domain found, it means that is relative!
                if (*full_url == '/') {
                    new_url_size = sprintf(output_buffer, "https://%s.%s:%d/?url=%s%.*s", originating_domain, enclave_domain, port, originating_domain, url_size, full_url);
                }
                else {
                    // need to add the /
                    new_url_size = sprintf(output_buffer, "https://%s.%s:%d/?url=%s/%.*s", originating_domain, enclave_domain, port, originating_domain, url_size, full_url);
                }   
            }
            else {
                new_url_size = sprintf(output_buffer, "https://%.*s.%s:%d/?url=%.*s", domain_size, domain, enclave_domain, port, url_size, full_url);
            }
            // printf("[DEBUG_REWRITING] Rewritten url: %.*s\n", new_url_size, output_buffer);

            slider += url_size;
            output_buffer += new_url_size;
        }
    }

    // printf("[DEBUG_REWRITING] Finished rewriting\n");
    return output_buffer - inital_output_buffer;
}

/**
 * Extract the content length header value from a chunk.
 * Remove the content length header from the chunk by replacing it with x
*/
int extract_length(char * chunk, int size) {
    // avoid edge cases where for unknown reasons even if there is some content left it is never received
    if (strstr(chunk, "301 Moved Permanently") != NULL) {
        return -1;
    }
    
    char * content_length = strstr(chunk, "Content-Length: ");
    if (content_length == NULL) {
        content_length = strstr(chunk, "content-length: ");
    }
    if (content_length == NULL) {
        return -1;
    }

    // must remove now the content length header from the chunk by replacing it with x
    memset(content_length, 'x', 16);

    content_length += 16; // skip "Content-Length: "
    char * end = strstr(content_length, "\r\n");
    if (end == NULL) {
        return -1;
    }
    *end = '\0'; // terminate the string
    return atoi(content_length);
}

/*
* I expect that whoever calls this has already opened the socket and conneted to it.
*/
void enc_HTTP_Request(const int sockfd, const url_t url, const WOLFSSL * ssl_writeback) {
    int ret; 
    int res;
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX*    ctx;
    WOLFSSL*        ssl;

    /*ret = wolfSSL_Debugging_ON();
    if (ret != 0) {
        ocall_print_string("Error setting debugging on\n");
        if (res == -174) {
            ocall_print_string("Error code: not compiled in!\n");
        }
    }
    else {
        ocall_print_string("Debugging on\n");
    }*/
   wolfSSL_Debugging_OFF();

    // Create and setup the SSL context
    method = wolfTLSv1_2_client_method();
    if (method == NULL) {
        ocall_print_string("wolfTLSv1_2_client_method failure\n");
        abort();
    }

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        ocall_print_string("wolfSSL_CTX_new failure\n");
        abort();
    }

    // Future improvement: do certificate pinning for every certificate
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

    // certificate pinning
    /* const char digiCert_Global_Root_G2_cert[] = "-----BEGIN CERTIFICATE-----\nMIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQG\nEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAw\nHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUx\nMjAwMDBaMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3\ndy5kaWdpY2VydC5jb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI2/Ou8jqJ\nkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx1x7e/dfgy5SDN67sH0NO\n3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQq2EGnI/yuum06ZIya7XzV+hdG82MHauV\nBJVJ8zUtluNJbd134/tJS7SsVQepj5WztCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyM\nUNGPHgm+F6HmIcr9g+UQvIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQAB\no0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV5uNu\n5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY1Yl9PMWLSn/pvtsr\nF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4NeF22d+mQrvHRAiGfzZ0JFrabA0U\nWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NGFdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBH\nQRFXGU7Aj64GxJUTFy8bJZ918rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/\niyK5S9kJRaTepLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl\nMrY=\n-----END CERTIFICATE-----\n";
    ret = wolfSSL_CTX_load_verify_buffer(ctx, digiCert_Global_Root_G2_cert, sizeof(digiCert_Global_Root_G2_cert), SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        printf("wolfSSL_CTX_use_certificate_chain_buffer_format failure. Error: %d\n", ret);
        return;
    } */          

    // Create the SSL object
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        ocall_print_string("wolfSSL_new failure\n");
        abort();
    }

    // Associate the socket with the SSL object
    ret = wolfSSL_set_fd(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
        ocall_print_string("wolfSSL_set_fd failure\n");
        abort();
    }

    // Perform the SSL/TLS handshake
    ret = wolfSSL_connect(ssl);
    if (ret != SSL_SUCCESS) {
        ocall_print_string("wolfSSL_connect failure\n");
        return ret;
    }

    ocall_print_string("SSL/TLS handshake completed\n");

    // create request with host
    char sendBuff[256];
    snprintf(sendBuff, sizeof(sendBuff), "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", url.path, url.host);

    // Send data to the server
    ret = wolfSSL_write(ssl, sendBuff, strlen(sendBuff));

    if (ret != strlen(sendBuff)) {
        // the message is not able to send, or error trying
        wolfSSL_get_error(ssl, ret);
        ocall_print_string("Write error");
        return EXIT_FAILURE;
    }

    ocall_print_string("[DEBUG_HTTP_REQUEST] Sent: \t");
    ocall_print_string(sendBuff);
    ocall_print_string("\n");

    // check if it needs rewriting, by default yes
    bool needs_rewriting = true;
    if (strstr(url.path, ".css") != NULL || strstr(url.path, ".js") != NULL || strstr(url.path, ".png") != NULL || strstr(url.path, ".jpg") != NULL || strstr(url.path, ".jpeg") != NULL || strstr(url.path, ".gif") != NULL || strstr(url.path, ".svg") != NULL || strstr(url.path, ".ico") != NULL) {
        needs_rewriting = false;
    }

    // Receive data from the server
    char * curr_chunk = malloc(RECV_BUFF_SIZE+1);
    char * next_chunk = malloc(RECV_BUFF_SIZE+1);
    char output[2 * RECV_BUFF_SIZE]; 
    int curr_size = 0;
    int next_size = 0;
    int output_size = 0;
    
    curr_size = wolfSSL_read(ssl, curr_chunk, RECV_BUFF_SIZE);
    curr_chunk[curr_size] = '\0';

    // this is the first chunk, thus we can extract from it the content length
    int content_length_left = extract_length(curr_chunk, curr_size);
    if (content_length_left == -1) {
        // printf("[DEBUG_HTTP_REQUEST] No content length found\n");
    }
    
    while(curr_size > 0) {
        // printf("[DEBUG_HTTP_REQUEST] Received chunk: %.*s\n", curr_size, curr_chunk);
        // printf("[DEBUG_HTTP_REQUEST] Content length left: %d\n", content_length_left);

        if (content_length_left > 0) {
            int to_read = RECV_BUFF_SIZE-1;
            if (content_length_left < RECV_BUFF_SIZE-1) {
                to_read = content_length_left;
            }
            next_size = wolfSSL_read(ssl, next_chunk, to_read);
            next_chunk[next_size] = '\0';
        }
        else {
            next_size = 0;
        }
        
        // rewrite urls in chunk
        if (needs_rewriting) {
            // printf("[DEBUG_HTTP_REQUEST] Rewriting urls\n");
            output_size = rewrite_urls(curr_chunk, curr_size, next_chunk, next_size, ENCLAVE_DOMAIN, ENCLAVE_PORT, url.host, output);

            // printf("[DEBUG_HTTP_REQUEST] Rewritten chunk: %.*s\n", output_size, output);
            // printf("[DEBUG_HTTP_REQUEST] Writing back size of %d\n", output_size);
            wolfSSL_write(ssl_writeback, output, output_size);  // Call the callback function
        }
        else {
            // printf("[DEBUG_HTTP_REQUEST] Writing back chunk without rewriting\n");
            wolfSSL_write(ssl_writeback, curr_chunk, curr_size);  // Call the callback function
        }
        
        // the next chunk now becomes the current chunk
        char * temp = curr_chunk;
        curr_chunk = next_chunk;
        next_chunk = temp; // will be overwritten in the next iteration
        content_length_left -= next_size;
        curr_size = next_size;
    }

    if (wolfSSL_want_read(ssl)) {
        // The connection needs to be read again
        // Future improvement: handle this case
    } else if (ret < 0) {
        // An error occurred
        int error = wolfSSL_get_error(ssl, ret);
        // Handle error...  
        // Future improvement: handle this case
    }

    // clean up
    // printf("[DEBUG_HTTP_REQUEST] Cleaning up\n");
    free(curr_chunk);
    free(next_chunk);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}

void enc_prepare_HTTP_request(const char * url, int * sockfd) {    
    int ret;
    char ip[16];

    ocall_getipfromdomain(url, ip, sizeof(ip));

    ocall_open_socket_and_connect(&ret, ip, 443, sockfd);
}

void serve_welcome_page(WOLFSSL * ssl_writeback) {
    const char* html_content =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<!DOCTYPE html>"
        "<html lang=\"en\">"
        "<head>"
        "<meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        "<title>Web Rehosting Explanation</title>"
        "<style>"
        "body { font-family: Arial, sans-serif; margin: 0; padding: 0; display: flex; flex-direction: column; min-height: 100vh; }"
        "header { background-color: #4CAF50; color: white; padding: 1em; text-align: center; }"
        "main { flex: 1; padding: 1em; }"
        "footer { background-color: #f1f1f1; text-align: center; padding: 1em; position: relative; bottom: 0; width: 100%; }"
        ".form-container { margin: 2em 0; }"
        "</style>"
        "</head>"
        "<body>"
        "<header><h1>Secure Web Rehosting</h1></header>"
        "<main>"
        "<section class=\"form-container\"><h2>Submit a URL for secure web rehosting</h2>"
        "<form method=\"GET\" action=\"\"><label for=\"url\">Enter URL: </label>"
        "<input id=\"url\" name=\"url\" required>"
        "<button type=\"submit\">Submit</button></form>"
        "</section>"
        "</main>"
        "<footer><p>&copy; 2024 Web Rehosting Inc.</p></footer>"
        "</body></html>";
    wolfSSL_write(ssl_writeback, html_content, strlen(html_content));
}

void enc_serve_HTTP_Request(int connd, WOLFSSL_CTX * ctx) {
    int ret; 
    int res;
    int sockfd;
    char               buff[256];
    size_t             len;
    WOLFSSL * ssl; 

    /*ret = wolfSSL_Debugging_ON();
    if (ret != 0) {
        ocall_print_string("Error setting debugging on\n");
        if (res == -174) {
            ocall_print_string("Error code: not compiled in!\n");
        }
    }
    else {
        ocall_print_string("Debugging on\n");
    }*/
    wolfSSL_Debugging_OFF();

    ssl = wolfSSL_new(ctx);

    wolfSSL_set_fd(ssl, connd);

    memset(buff, 0, sizeof(buff));
    wolfSSL_read(ssl, buff, sizeof(buff)-1);

    printf("[DEBUG_SERVE_GET] Client request:\n%s\n\n", buff);
    // parse request to extract the url to which do the GET request
    // request is of format GET /?url=TOEXTRACT HTTP/1.X

    // 3 cases supported:
    // - a request to / was made, hence need to serve back the home page
    // - a request with /?url=, so we follow the url
    // - a request with custom subdomain but no /?url= was made, probably a relative url not catched by the rewriting engine, 
    //   serve it using the subdomain as main domain
    char * url;
    char * to_match[1024];
    memset(to_match, '\0', 1024);
    sprintf(to_match, "Host: %s", ENCLAVE_DOMAIN);
    if (strstr(buff, "GET / ") != NULL) {
        printf("[DEBUG_SERVE_GET] Serving welcome page\n");
        serve_welcome_page(ssl);
    }
    else if (url = strstr(buff, "/?url=")) {
        printf("[DEBUG_SERVE_GET] Request with url parameter\n");
        if (url == NULL) {
            ocall_print_string("Error: no url found in request\n");
            return;
        }
        url += 6; // skip /?url=
        char * end = strstr(url, " ");
        if (end == NULL) {
            ocall_print_string("Error: no end of url found in request\n");
            return;
        }
        *end = '\0'; // terminate the url string
        url_t parsed_url;
        ret = parse_and_decode_url(url, &parsed_url);
        if (ret != 0) {
            ocall_print_string("Error parsing url\n");
            return;
        }
        printf("[DEBUG_SERVE_GET] Parsed url: %s and %s\n", parsed_url.host, parsed_url.path);

        enc_prepare_HTTP_request(parsed_url.host, &sockfd);
        enc_HTTP_Request(sockfd, parsed_url, ssl);
    }
    else if (strstr(buff, to_match) == NULL && strstr(buff, "Host: ") != NULL){
        printf("[DEBUG_SERVE_GET] Request with no url parameter\n");
        
        // get domain from host
        char * domain_start = strstr(buff, "Host: ");
        domain_start += 6; // skip Host:
        char * domain_end = strstr(domain_start, ENCLAVE_DOMAIN);
        domain_end -= 1; // account for "." that comes before
        *domain_end = '\0';
        printf("[DEBUG_SERVE_GET] Got domain %s\n", domain_start);
        
        // get full path
        char * path_start = strstr(buff, "GET ");
        if (path_start == NULL) {
            ocall_print_string("[WARNING] no GET found in request. POST etc are not supported yet\n");
            return;
        }

        path_start += 4; // skip GET 
        char * path_end = strstr(path_start, " ");
        if (path_end == NULL) {
            ocall_print_string("[ERROR] no end of url found in request\n");
            return;
        }
        *path_end = '\0'; // terminate the url string
        printf("[DEBUG_SERVE_GET] Got path %s\n", path_start);

        // add the / in front if needed
        if (*path_start != '/') {
            path_start -= 1;
            *path_start = '/';
        }

        url_t parsed_url;
        strncpy(parsed_url.host, domain_start, sizeof(parsed_url.host) - 1);
        url_decode(path_start, parsed_url.path);

        printf("[DEBUG_SERVE_GET] Parsed url: %s and %s\n", parsed_url.host, parsed_url.path);

        enc_prepare_HTTP_request(parsed_url.host, &sockfd);
        enc_HTTP_Request(sockfd, parsed_url, ssl);
    }
    else {
        const char* html_content = "Not supported :(";
        wolfSSL_write(ssl, html_content, strlen(html_content));
    }
    
}


void enc_create_key_and_x509(WOLFSSL_CTX* ctx) {
    uint8_t der_key[2048];
    uint8_t der_cert[8 * 1024];
    uint32_t der_key_len = sizeof(der_key);
    uint32_t der_cert_len = sizeof(der_cert);

    create_key_and_x509(&der_key, &der_key_len,
                        &der_cert, &der_cert_len,
                        &my_ra_tls_options);

    int ret;
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, der_cert, der_cert_len,
                                             SSL_FILETYPE_ASN1);
    assert(ret == SSL_SUCCESS);

    wolfSSL_CTX_use_PrivateKey_buffer(ctx, der_key, der_key_len,
                                      SSL_FILETYPE_ASN1);
    assert(ret == SSL_SUCCESS);
}

int enc_wolfSSL_Init(void)
{
    return wolfSSL_Init();
}

WOLFSSL_METHOD* enc_wolfTLSv1_2_client_method(void)
{
    return wolfTLSv1_2_client_method();
}

WOLFSSL_METHOD* enc_wolfTLSv1_2_server_method(void)
{
    return wolfTLSv1_2_server_method();
}


WOLFSSL_CTX* enc_wolfSSL_CTX_new(WOLFSSL_METHOD* method)
{
    if(sgx_is_within_enclave(method, wolfSSL_METHOD_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_new(method);
}

void enc_wolfSSL_Debugging_ON(void)
{
    wolfSSL_Debugging_ON();
}
