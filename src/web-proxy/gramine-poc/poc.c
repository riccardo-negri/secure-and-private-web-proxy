#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>
#include <curl/curl.h>

#define PORT 8080

// structure to hold accumulated response data
struct ResponseData {
    char *buffer;       // buffer to hold the accumulated response data
    size_t buffer_size; // current size of the buffer
};

// write callback function for libcurl to handle response
static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    struct ResponseData *response_data = (struct ResponseData *)userdata;
    size_t data_size = size * nmemb;

    // reallocating buffer to accommodate new data
    char *new_buffer = realloc(response_data->buffer, response_data->buffer_size + data_size);
    if (new_buffer == NULL) {
        // error handling: unable to allocate memory
        return 0;
    }
    response_data->buffer = new_buffer;

    // copying new data to the buffer
    memcpy(response_data->buffer + response_data->buffer_size, ptr, data_size);
    response_data->buffer_size += data_size;

    return data_size; // return number of bytes processed
}

// callback function for handling HTTP requests
static int request_handler(void *cls, struct MHD_Connection *connection, const char *url,
                           const char *method, const char *version, const char *upload_data,
                           size_t *upload_data_size, void **con_cls) {
    if (strcmp(method, "GET") == 0 && strcmp(url, "/") == 0) {
        // serve the main page with the form
        const char *page = "<html><body><form action=\"/proxy\" method=\"GET\">"
                           "<input type=\"text\" name=\"url\"><input type=\"submit\" value=\"Visit\"></form>"
                           "</body></html>";
        struct MHD_Response *response = MHD_create_response_from_buffer(strlen(page), (void *)page, MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/proxy") == 0) {
        // handle form submission
        const char *proxy_url= MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "url");
        if (proxy_url) {
            CURL *curl = curl_easy_init();
            if (curl) {
                // allocate ResponseData structure to hold accumulated response data
                struct ResponseData response_data = {NULL, 0};

                CURLcode res;
                // set the URL to be proxied
                curl_easy_setopt(curl, CURLOPT_URL, proxy_url);

                // perform the request
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);  // follow redirects

                // set write callback function to receive response
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);  // pass ResponseData as userdata

                res = curl_easy_perform(curl);

                if (res == CURLE_OK) {
                    // request successful
                    struct MHD_Response *response = MHD_create_response_from_buffer(response_data.buffer_size, response_data.buffer, MHD_RESPMEM_MUST_COPY);
                    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
                    MHD_destroy_response(response);

                    // clean up allocated memory
                    free(response_data.buffer);

                    curl_easy_cleanup(curl);
                    return ret;
                } else {
                    // handle request error
                    // clean up allocated memory
                    free(response_data.buffer);

                    curl_easy_cleanup(curl);
                    return MHD_NO;
                }
            }
        } else {
            // invalid form submission
            const char *error_page = "<html><body><h1>Invalid URL</h1></body></html>";
            struct MHD_Response *response = MHD_create_response_from_buffer(strlen(error_page), (void *)error_page, MHD_RESPMEM_PERSISTENT);
            int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
            MHD_destroy_response(response);
            return ret;
        }
    }
    
    // invalid request
    return MHD_HTTP_NOT_FOUND;
}

int main() {
    struct MHD_Daemon *daemon;

    // start the web server
    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL, &request_handler, NULL, MHD_OPTION_END);
    if (!daemon) {
        printf("failed to start the server\n");
        return 1;
    }

    printf("server running on port %d...\n", PORT);
    getchar();  // wait for user input to stop the server

    // stop the web server
    MHD_stop_daemon(daemon);

    return 0;
}

