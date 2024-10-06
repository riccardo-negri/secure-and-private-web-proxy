#include <stdio.h> 
#include <stdbool.h>

extern struct ra_tls_options my_ra_tls_options;

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
    return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
    return ret;
}

int LowResTimer(void) /* low_res timer */
{
    int time;
    ocall_low_res_time(&time);
    return time;
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

int sprintf(char* buf, const char *fmt, ...)
{
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    return ret;
}

int snprintf(char* str, size_t size, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(str, size, format, args);
    va_end(args);

    return ret;
}

typedef struct {
    char host[256];
    char path[1024];
} url_t;

int parse_and_decode_url(const char* encoded_url, url_t * result) {
    char decoded_url[1024];
    url_decode(encoded_url, decoded_url);

    // initialize the result
    memset(result, 0, sizeof(url_t));

    // find the start of the host
    const char* host = strstr(decoded_url, "://");
    if (host != NULL) {
        host += 3; // Skip past ://
    } else {
        host = decoded_url;
    }

    // find the end of the host
    const char* path = strchr(host, '/');
    if (path == NULL) {
        // the URL doesn't have a path, in this case set / as the path
        strncpy(result->host, host, sizeof(result->host) - 1);
        strncpy(result->path, "/", sizeof(result->path) - 1); // Set path to "/"
        return 0;
    }

    // copy the host and path into the result
    size_t host_len = path - host;
    if (host_len > sizeof(result->host) - 1) {
        host_len = sizeof(result->host) - 1;
    }
    strncpy(result->host, host, host_len);
    strncpy(result->path, path, sizeof(result->path) - 1);

    return 0;
}

void url_decode(const char *src, char *dst) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}


void * mymemcpy(void *dest, const void *src, int n, const char * debug_string) {
    if (n < 0) {
        printf("[WARNING] Called memcpy with negative size: %d. Now I will die, so you can debug!\n", n);
        printf("[WARNING] Debug string: %s\n", debug_string);
        assert(false);
    }
    if (n > 0) {
        return memcpy(dest, src, n);
    }    
}