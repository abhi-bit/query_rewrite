//C libraries
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>

// C++ libraries
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <streambuf>
#include <string>
#include <vector>

#include <evhtp.h>
#include "http_parser.h"
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include "uv.h"

#define CHECK(status, msg) \
    if (status != 0) { \
        fprintf(stderr, "%s: %s\n", msg, uv_err_name(status)); \
        exit(1); \
    }
#define UV_ERR(err, msg) fprintf(stderr, "%s: %s\n", msg, uv_err_name(err))
#define LOG_ERROR(msg) puts(msg)
#define LOG(msg) puts(msg)
#define LOGF(...) printf(__VA_ARGS__)

static uv_loop_t *uv_loop;
static http_parser_settings req_parser_settings;
static int request_num = 1000;

std::map<std::string, std::vector<int> > partitionStates;

typedef struct {
    evhtp_request_t *req;
    uint64_t        limit;
} lookup_ctx;

typedef unsigned char UChar;

struct app {
    struct app_parent *parent;
    evbase_t          *evbase;
};

struct client_t {
    client_t()      :   body() {};
    http_parser         parser;
    int                 request_num;
    uv_tcp_t            tcp;
    uv_connect_t        connect_req;
    uv_shutdown_t       shutdown_req;
    uv_write_t          write_req;
    std::stringstream   body;
};
