#include "cquery.h"
#include "vbmap.h"
#include "view_file_reader.h"

typedef struct {
    tree_file *file;
    uint64_t root_pointer;
} request_ctx;

struct app_parent {
    evhtp_t     *evhtp;
    evbase_t    *evbase;
    tree_file   *file;
    uint64_t    root_pointer;
};

void alloc_callback_buffer(uv_handle_t *handle, size_t suggested_size,
                           uv_buf_t *buf)
{
    *buf = uv_buf_init((char *) malloc(suggested_size), suggested_size);
}

void on_close(uv_handle_t *handle)
{
    client_t *client = (client_t *) handle->data;
    LOGF("on close\n");
    delete client;
}

void on_read(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf)
{
    ssize_t parsed;
    client_t *client = (client_t *) tcp->data;
    LOGF("on read: %ld\n", nread);
    LOGF("on read buf.size: %ld\n", buf->len);
    if (nread > 0) {
        http_parser *parser = &client->parser;
        if (parser->http_errno == HPE_PAUSED) {
            LOGF("on_read paused\n");
            return;
        }
        parsed = (ssize_t) http_parser_execute(parser, &req_parser_settings,
                                               buf->base, nread);
        if (parser->upgrade) {
            LOGF("parser upgrade not supported\n");
        } else if (parsed != nread) {
            LOGF("parsed incomplete data: %ld/%ld bytes parsed\n",
                                            parsed, nread);
            LOGF("\n*** %s ***\n",
                  http_errno_description(HTTP_PARSER_ERRNO(parser)));
        }
    } else {
        if (nread != UV_EOF) {
            UV_ERR(nread, "read");
        }
    }
    free(buf->base);
}

void after_write(uv_write_t *req, int status)
{
    LOGF("after write\n");
    CHECK(status, "write");
}

void on_connect(uv_connect_t *req, int status)
{
    client_t *client = (client_t *) req->handle->data;

    if (status == -1) {
        fprintf(stderr, "connect failed error %s\n", uv_err_name(status));
        uv_close((uv_handle_t *) req->handle, on_close);
        return;
    }

    client->request_num++;

    LOGF("[ %5d ] new connection\n", client->request_num);

    uv_buf_t resbuf;
    std::string res = "GET /query HTTP/1.1\r\n"
                      "Host: 0.0.0.0=8081\r\n"
                      "User-Agent: client\r\n"
                      "Keep-Alive: 100\r\n"
                      "Connection: keep-alive\r\n"
                      "\r\n";
    resbuf.base = (char *) res.c_str();
    resbuf.len  = res.size();

    int rr      = uv_read_start(req->handle, alloc_callback_buffer, on_read);
    CHECK(rr, "bind");

    int r       = uv_write(&client->write_req,
                           req->handle,
                           &resbuf,
                           1,
                           after_write);
    CHECK(r, "bind");
}

int on_message_begin(http_parser *parser)
{
    LOGF("\n*** MESSAGE BEGIN ***\n");
    return 0;
}

int on_headers_complete(http_parser *parser)
{
    LOGF("\n***HEADERS COMPLETE***\n");
    return 0;
}

int on_url(http_parser *parser, const char *at, size_t length)
{
    LOGF("URL: %.*s\n", (int) length, at);
    return 0;
}

int on_header_field(http_parser *parser, const char *at, size_t length)
{
    LOGF("Header Field: %.*s\n", (int) length, at);
    return 0;
}

int on_header_value(http_parser *parser, const char *at, size_t length)
{
    LOGF("Header Value: %.*s\n", (int) length, at);
    return 0;
}

int on_body(http_parser *parser, const char *at, size_t length)
{
    LOGF("Body: %d\n", (int) length);
    client_t *client = (client_t *) parser->data;

    if (at && client) {
        client->body << std::string(at, length);
    }
    return 0;
}

int on_message_complete(http_parser *parser)
{
    LOGF("\n***MESSAGE COMEPLETE***\n");
    client_t *client = (client_t *) parser->data;
    ssize_t total_len = client->body.str().size();
    LOGF("total length parsed: %ld\n", total_len);

    if (http_should_keep_alive(parser)) {
        LOGF("\n***SHOULD CLOSE Keepalive here***\n");
        uv_stream_t *tcp = (uv_stream_t *) &client->tcp;
        uv_close((uv_handle_t *) tcp, on_close);
    }
    return 0;
}

void on_resolved(uv_getaddrinfo_t *req, int status, struct addrinfo *res)
{
    if (status == -1) {
        fprintf(stderr, "getaddrinfo callback error %s\n", uv_err_name(status));
        return;
    }

    char addr[17] = {'\0'};
    uv_ip4_name((struct sockaddr_in *) res->ai_addr, addr, 16);
    LOGF("resolved to %s\n", addr);
    uv_freeaddrinfo(res);
    struct sockaddr_in dest;
    int r = uv_ip4_addr(addr, 8000, &dest);
    CHECK(r, "ip4_addr");

    for (int i = 0; i < request_num; i++) {
        client_t *client = new client_t();
        client->request_num = request_num;
        client->tcp.data = client;
        http_parser_init(&client->parser, HTTP_RESPONSE);
        client->parser.data = client;
        // check docs
        r = uv_tcp_init(uv_loop, &client->tcp);
        CHECK(r, "tcp_init");
        // check docs
        r = uv_tcp_keepalive(&client->tcp, 1, 60);
        CHECK(r, "tcp_keepalive");
        r = uv_tcp_connect(&client->connect_req, &client->tcp,
                           (const struct sockaddr *) &dest, on_connect);
        CHECK(r, "tcp_connect");
    }
    LOGF("Listening on port 8081\n");
}

#ifndef EVHTP_DISABLE_EVTHR
static evthr_t *get_request_thr(evhtp_request_t *request)
{
    evhtp_connection_t *htpconn;
    evthr_t            *thread;

    htpconn = evhtp_request_get_connection(request);
    thread  = htpconn->thread;

    return thread;
}
#endif

static couchstore_error_t lookup_callback(couchfile_lookup_request *rq,
                                          const sized_buf *k,
                                          const sized_buf *v)
{
    const uint16_t json_key_len = decode_raw16(*((raw_16 *) k->buf));
    sized_buf json_key;
    sized_buf json_value;

    json_key.buf = k->buf + sizeof(uint16_t);
    json_key.size = json_key_len;

    json_value.size = v->size - sizeof(raw_kv_length);
    json_value.buf = v->buf + sizeof(raw_kv_length);

    evbuf_t    * buf;
    lookup_ctx *ctx = (lookup_ctx *) rq->callback_ctx;

    buf = evbuffer_new();

    evbuffer_add(buf, json_key.buf, json_key.size);
    evbuffer_add(buf, json_value.buf, json_value.size);
    evbuffer_add(buf, "\n", 1);

    evhtp_send_reply_chunk(ctx->req, buf);

    evbuffer_drain(buf, -1);

    evbuffer_free(buf);

    ctx->limit--;
    if (ctx->limit > 0) {
      return (couchstore_error_t) 1;
    }
    else {
      return (couchstore_error_t) -1;
    }
    rq->num_keys++;

    return COUCHSTORE_SUCCESS;
}

static void subquery(evhtp_request_t *req, void * arg)
{
    request_ctx *ctx = (request_ctx *)arg;
    lookup_ctx lookup_ctx = {req, 5};

    sized_buf nullkey = {NULL, 0};
    sized_buf *lowkeys = &nullkey;
    couchfile_lookup_request rq;

    rq.cmp.compare = view_btree_cmp;
    rq.file = ctx->file;
    rq.num_keys = 1;
    rq.keys = &lowkeys;
    rq.callback_ctx = &lookup_ctx;
    rq.fetch_callback = lookup_callback;
    rq.node_callback = NULL;
    rq.fold = 1;

    evhtp_send_reply_chunk_start(req, EVHTP_RES_OK);
    btree_lookup(&rq, ctx->root_pointer);
    evhtp_send_reply_chunk_end(req);
}

static void query(evhtp_request_t *req, void *arg)
{
    std::vector<std::string> nodeList;
    for (std::map<std::string,
        std::vector<int> >::iterator it = partitionStates.begin();
        it != partitionStates.end(); ++it) {
        nodeList.push_back(it->first);
    }
}

#ifndef EVHTP_DISABLE_EVTHR
void app_process_request(evhtp_request_t *request, void *arg)
{
    struct sockaddr_in *sin;
    //struct app_parent  *app_parent;
    struct app         *app;
    evthr_t            *thread;
    evhtp_connection_t *conn;
    //char                tmp[1024];

    printf("process request(%p)\n", request);

    thread = get_request_thr(request);
    conn   = evhtp_request_get_connection(request);
    app    = (struct app *) evthr_get_aux(thread);
    sin    = (struct sockaddr_in *) conn->saddr;

    request_ctx *ctx = (request_ctx *)arg;
    lookup_ctx lookup_ctx = {request, 5};

    sized_buf nullkey = {NULL, 0};
    sized_buf *lowkeys = &nullkey;
    couchfile_lookup_request rq;

    rq.cmp.compare = view_btree_cmp;
    rq.file = ctx->file;
    rq.num_keys = 1;
    rq.keys = &lowkeys;
    rq.callback_ctx = &lookup_ctx;
    rq.fetch_callback = lookup_callback;
    rq.node_callback = NULL;
    rq.fold = 1;

    evhtp_send_reply_chunk_start(request, EVHTP_RES_OK);
    btree_lookup(&rq, ctx->root_pointer);
    evhtp_send_reply_chunk_end(request);
}
#endif

#ifndef EVHTP_DISABLE_EVTHR
void app_init_thread(evhtp_t *htp, evthr_t *thread, void *arg)
{
    struct app_parent *app_parent;
    struct app        *app;

    app_parent = (struct app_parent *)arg;
    app        = calloc(sizeof(struct app), 1);

    app->parent = app_parent;
    app->evbase = evthr_get_base(thread);

    evthr_set_aux(thread, app);
}
#endif

int main(int argc, char ** argv)
{
    evbase_t            *evbase;
    evhtp_t             *evhtp;
#ifndef EVHTP_DISABLE_EVTHR
    struct app_parent   *app_p;
#endif
    tree_file           *file;
    UChar               *queryPattern;
    UChar               *subqueryPattern;
    struct rlimit       limit;

    // partition map
    partitionStates= get_partiton_map();

    for (std::map<std::string,
         std::vector<int> >::iterator it = partitionStates.begin();
         it != partitionStates.end(); ++it) {
        std::cout << it->first << " => ";
        for (int j = 0; j < it->second.size(); j++) {
            std::cout << it->second[j] << " ";
        }
        std::cout << std::endl;
    }

    getrlimit(RLIMIT_NOFILE, &limit);
    LOGF("current ulimit: %ld\n", limit.rlim_cur);

    uint64_t root_pointer = 0;

    evbase              = event_base_new();
    evhtp               = evhtp_new(evbase, NULL);
#ifndef EVHTP_DISABLE_EVTHR
    app_p               = calloc(sizeof(struct app_parent), 1);
#endif

    file = (tree_file *) calloc(1, sizeof(*file));
    open_view_file("/var/tmp/pymc0_index", &file, &root_pointer);
    fprintf(stdout, "root pos %ld\n", root_pointer);

    request_ctx ctx = {file, root_pointer};

#ifndef EVHTP_DISABLE_EVTHR
    app_p->evhtp        = evhtp;
    app_p->evbase       = evbase;
    app_p->file         = file;
    app_p->root_pointer = root_pointer;
#endif

    queryPattern = (UChar *)"query";
    subqueryPattern = (UChar *)"_subquery";

    //evhtp_set_regex_cb(evhtp, (const char *) queryPattern,
    //                   query, (void *)&ctx);
    evhtp_set_regex_cb(evhtp, (const char *) subqueryPattern,
                       subquery, (void *)&ctx);
#ifndef EVHTP_DISABLE_EVTHR
    evhtp_set_cb(evhtp, "/query", app_process_request, (void *)&ctx);
    evhtp_set_cb(evhtp, "/_set_view/query", app_process_request, (void *)&ctx);
    evhtp_use_threads(evhtp, app_init_thread, 8, NULL);
#endif
    evhtp_bind_socket(evhtp, "0.0.0.0", 8081, 2048);

    event_base_loop(evbase, 0);

    evhtp_unbind_socket(evhtp);
    evhtp_free(evhtp);
    event_base_free(evbase);

    return 0;
}
