// Copyright © 2018-2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

/*****************************************************************************
    Memory server
    - memory management at one server
    - local memory allocation and RDMA registration
    - register w/ the rack controller and expose memory to the rack
 ****************************************************************************/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <infiniband/verbs.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "base/log.h"
#include "rmem/rdma.h"

static struct context *s_ctx = NULL;
static volatile bool aborted = false;

struct rcntrl_conn_t;
struct client_list_t;
struct server_t;

struct {
    // TODO: remove rcntrl and rcport,
    // and set _rcntrl.ip and _rcntrl.port directly
    char rcntrl[200];
    int rcport;
    char server[200];
    int port;
    uint64_t num_slabs;
    // TODO: eliminate global rrs
    /* rrs points to the rrs in the server_run function */
    struct server_t *rrs;
} globals;

struct rcntrl_conn_t {
    char ip[200];
    int port;
    uint64_t rdmakey;
    struct rdma_event_channel *rchannel;
    struct rdma_cm_id *rid;
} _rcntrl;

struct server_t {
    struct rdma_cm_id *rid;
    struct rdma_event_channel *rchannel;

    struct ibv_mr *mr;
    uint64_t base_addr;
    uint64_t rdma_key;
};

struct client_info_t {
    // pointer to active client list
    struct client_list_t *lstptr;
};

struct client_list_t {
    struct client_info_t *client;
    struct client_list_t *next;
    struct client_list_t *prev;
} * _clilst_head, *_clilst_tail;

/**********************************
 ***********************************/

static int on_connect_request(struct rdma_cm_id *id);
static int on_connection(struct rdma_cm_id *id);
static int on_disconnect(struct rdma_cm_id *id);
static void process_event(struct rdma_cm_event *event);
static void build_context(struct ibv_context *verbs);

static inline void *xmalloc(size_t size) {
    void *ptr = malloc(size);
    assert(ptr);
    return ptr;
}

/**********************************
 signal handler
 ***********************************/

void sig_handler(int sig) {
    if (sig == SIGINT) aborted = true;
}

void register_signal_handler(void) {
    int r;
    struct sigaction sigint_handler = {.sa_handler = sig_handler};

    sigemptyset(&sigint_handler.sa_mask);

    r = sigaction(SIGINT, &sigint_handler, NULL);
    if (r < 0) log_err("could not register signal handler");
}

/************************************
    client list management
***********************************/

static void clilst_init() {
    _clilst_head = (struct client_list_t *)xmalloc(sizeof(struct client_list_t));
    _clilst_tail = (struct client_list_t *)xmalloc(sizeof(struct client_list_t));
    _clilst_head->client = NULL;
    _clilst_tail->client = NULL;
    _clilst_head->next = _clilst_tail;
    _clilst_head->prev = NULL;
    _clilst_tail->next = NULL;
    _clilst_tail->prev = _clilst_head;
}

static void clilst_add(struct client_info_t *cli) {
    log_debug("clilst adding client %p link %p head %p tail %p", cli, cli->lstptr,
                     _clilst_head, _clilst_tail);

    struct client_list_t *newcli =
            (struct client_list_t *)xmalloc(sizeof(struct client_list_t));
    cli->lstptr = newcli;
    newcli->client = cli;
    newcli->next = _clilst_head->next;
    newcli->prev = _clilst_head;
    newcli->next->prev = newcli;
    _clilst_head->next = newcli;
}

static void clilst_remove(struct client_info_t *cli) {
    assert(cli);

    log_debug("clilst remove client %p link %p head %p tail %p", cli, cli->lstptr,
        _clilst_head, _clilst_tail);

    struct client_list_t *oldcli = cli->lstptr;

    assert(oldcli != _clilst_head);
    assert(oldcli != _clilst_tail);

    oldcli->prev->next = oldcli->next;
    oldcli->next->prev = oldcli->prev;

    free(oldcli->client);
    free(oldcli);
}

static void clilst_destroy() {
    log_debug("clilst destroy");
    struct client_list_t *cli = _clilst_head->next;
    struct client_list_t *oldcli = NULL;

    while (cli != _clilst_tail) {
        oldcli = cli;
        cli = cli->next;
        clilst_remove(oldcli->client);
    }

    log_debug("freeing head %p and tail %p", _clilst_head, _clilst_tail);
    free(_clilst_head);
    free(_clilst_tail);
}

/***********************************
    export memory
 ***********************************/

static void server_export_memory(struct server_t *rrs, uint64_t num_slabs,
                                                                 size_t slab_size) {
    void *ptr = NULL;
    size_t size = slab_size * num_slabs;

    log_info("exporting memory... num_slabs:%lu slab_size:%lu total:%lu",
                    num_slabs, slab_size, size);
    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
         -1, 0);
    if (ptr == MAP_FAILED) {
        log_err("error allocating memory region memory");
        assert(ptr != MAP_FAILED);
    }

    memset(ptr, 0, size);
    rrs->base_addr = (uint64_t)ptr;

    log_debug("server offering memory at %p %lu, size %lu", ptr, rrs->base_addr,
                     size);

    struct ibv_mr *mr = NULL;
    mr = ibv_reg_mr(s_ctx->pd, ptr, size, IBV_ACCESS_LOCAL_WRITE | 
        IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
    assert(mr);

    rrs->mr = mr;
    rrs->rdma_key = mr->rkey;
    log_info("done exporting memory!");
}

/******************************************
    rcntrl protocol
 ******************************************/

void send_msg_server_add(struct connection *conn) {
    log_debug("sending MSG_SERVER_ADD");

    conn->send_msg->type = MSG_SERVER_ADD;
    strcpy(conn->send_msg->data.ip, globals.server);
    conn->send_msg->data.port = globals.port;
    conn->send_msg->data.nslabs = globals.num_slabs; /*RDMA_SERVER_NSLABS;*/
    conn->send_msg->data.addr = (void *)globals.rrs->base_addr;
    conn->send_msg->data.rdmakey = globals.rrs->rdma_key;
    send_message(conn);

    // TODO: wait for notificaiton from controller that
    // server was successfully added
}

void send_msg_server_rem(struct connection *conn) {
    log_debug("sending MSG_SERVER_REM");

    conn->send_msg->type = MSG_SERVER_REM;
    strcpy(conn->send_msg->data.ip, globals.server);
    send_message(conn);
}

void on_recv_done(struct connection *conn) {
    log_debug("received done! %p", conn->recv_msg->data.addr);
}

void on_completion_client(struct ibv_wc *wc, enum ibv_wc_opcode opcode,
                                                    int msgtype) {
    struct connection *conn = (struct connection *)(uintptr_t)wc->wr_id;

    if (wc->status != IBV_WC_SUCCESS) {
        log_err("RDMA request failed with status %d: %s", wc->status,
               ibv_wc_status_str(wc->status));
    }
    assert(wc->status == IBV_WC_SUCCESS);

    if (wc->opcode & IBV_WC_RECV) {
        assert(opcode == IBV_WC_RECV);
        assert(conn->recv_msg->type == msgtype);

        switch (conn->recv_msg->type) {
            case MSG_DONE:
                on_recv_done(conn);
                break;
            default:
                BUG();
        }
    } else {
        if (opcode == IBV_WC_SEND) {
            assert(conn->send_msg->type == msgtype);
            log_debug("send completed successfully %p msg %d.", conn,
                   conn->send_msg->type);
        } else {
            assert(opcode == IBV_WC_RDMA_READ || opcode == IBV_WC_RDMA_WRITE);
            log_debug("RDMA READ/WRITE completed successfully");
        }
    }
}

void register_memory_client(struct connection *conn) {
    conn->send_msg = xmalloc(sizeof(struct message));
    conn->recv_msg = xmalloc(sizeof(struct message));

    conn->send_mr = ibv_reg_mr(s_ctx->pd, conn->send_msg, 
        sizeof(struct message), IBV_ACCESS_LOCAL_WRITE);
    assert(conn->send_mr);

    conn->recv_mr = ibv_reg_mr(s_ctx->pd, conn->recv_msg, 
        sizeof(struct message), IBV_ACCESS_LOCAL_WRITE);
    assert(conn->recv_mr);
}

void build_context_client(struct ibv_context *verbs) {
    if (s_ctx) {
        assert(s_ctx->ctx == verbs);
        return;
    }

    s_ctx = (struct context *)xmalloc(sizeof(struct context));
    s_ctx->ctx = verbs;
    s_ctx->pd = ibv_alloc_pd(s_ctx->ctx);
    assert(s_ctx->pd);
     s_ctx->comp_channel = ibv_create_comp_channel(s_ctx->ctx);
    assert(s_ctx->comp_channel);
       s_ctx->cq = ibv_create_cq(s_ctx->ctx, 10, NULL, s_ctx->comp_channel, 0); /* cqe=10 is arbitrary*/
    assert(s_ctx->cq);

      //int ret = pthread_create(&s_ctx->cq_poller_thread, NULL, poll_cq, NULL);
    //assertz(ret);
}

void build_qp_attr_client(struct ibv_qp_init_attr *qp_attr) {
    memset(qp_attr, 0, sizeof(*qp_attr));

    qp_attr->send_cq = s_ctx->cq;
    qp_attr->recv_cq = s_ctx->cq;
    qp_attr->qp_type = IBV_QPT_RC;

    qp_attr->cap.max_send_wr = 10;
    qp_attr->cap.max_recv_wr = 10;
    qp_attr->cap.max_send_sge = 1;
    qp_attr->cap.max_recv_sge = 1;
}

void build_connection_client(struct rdma_cm_id *id) {
    struct connection *conn;
    struct ibv_qp_init_attr qp_attr;
    int ret;

    build_context_client(id->verbs);
    build_qp_attr_client(&qp_attr);

    ret = rdma_create_qp(id, s_ctx->pd, &qp_attr);
    assertz(ret);

    id->context = conn = (struct connection *)xmalloc(sizeof(struct connection));

    conn->id = id;
    conn->qp = id->qp;
    conn->peer = NULL;

    conn->connected = 0;

    register_memory_client(conn);
    post_receives(conn);
}

int on_addr_resolved(struct rdma_cm_id *id) {
    int ret;
    log_debug("address resolved.");

    build_connection_client(id);
    ret = rdma_resolve_route(id, TIMEOUT_IN_MS);
    assertz(ret);
    return 0;
}

int on_route_resolved(struct rdma_cm_id *id) {
    struct rdma_conn_param cm_params;
    int ret;

    log_debug("route resolved.\n");
    build_params(&cm_params);
    ret = rdma_connect(id, &cm_params);
    assertz(ret);

    return 0;
}

int on_connection_client(struct rdma_cm_id *id) {
    log_debug("on connection");

    struct connection *conn = (struct connection *)id->context;
    conn->connected = 1;
    usleep(20);
    send_msg_server_add(conn);
    return 1;
}

int on_disconnect_client(struct rdma_cm_id *id) {
    log_debug("disconnected.");

    destroy_connection((struct connection *)id->context);
    return 1; /* exit event loop */
}

int on_event(struct rdma_cm_event *event) {
    int r = 0;

    log_debug("on_event client");

    if (event->event == RDMA_CM_EVENT_ADDR_RESOLVED)
        r = on_addr_resolved(event->id);
    else if (event->event == RDMA_CM_EVENT_ROUTE_RESOLVED)
        r = on_route_resolved(event->id);
    else if (event->event == RDMA_CM_EVENT_ESTABLISHED)
        r = on_connection_client(event->id);
    else if (event->event == RDMA_CM_EVENT_DISCONNECTED)
        r = on_disconnect_client(event->id);
    else {
        log_err("on_event: %d status: %d\n", event->event, event->status);
        log_err("Unknown event: is server running?");
        BUG();
    }

    return r;
}

/****************************************/

void rcntrl_connect(struct rcntrl_conn_t *rrc) {
    struct rdma_cm_event *event = NULL;

    // initiate connection
    while (rdma_get_cm_event(rrc->rchannel, &event) == 0) {
        struct rdma_cm_event event_copy;

        memcpy(&event_copy, event, sizeof(*event));
        rdma_ack_cm_event(event);

        if (on_event(&event_copy)) break;
    }

    log_info("client connected!");
}

void rcntrl_create(struct rcntrl_conn_t *rrc) {
    char portstr[10];
    struct addrinfo *addr = NULL;
    int ret;

    sprintf(portstr, "%d", rrc->port);
    log_info("client connection to server %s on port %s", rrc->ip, portstr);
    ret = getaddrinfo(rrc->ip, portstr, NULL, &addr);
    assertz(ret);

    rrc->rchannel = rdma_create_event_channel();
    assert(rrc->rchannel);
    ret = rdma_create_id(rrc->rchannel, &(rrc->rid), NULL, RDMA_PS_TCP);
    assertz(ret);
    ret = rdma_resolve_addr(rrc->rid, NULL, addr->ai_addr, TIMEOUT_IN_MS);
    assertz(ret);

    assert(addr != NULL);
    freeaddrinfo(addr);
}

void rcntrl_destroy(struct rcntrl_conn_t *rrc) {
    rdma_destroy_event_channel(rrc->rchannel);
}

void connect2rcntrl(char *rc_ip, int rc_port) {
    log_debug("Connecting to rcntrl on %s:%d\n", rc_ip, rc_port);

    strcpy(_rcntrl.ip, rc_ip);
    _rcntrl.port = rc_port;

    rcntrl_create(&_rcntrl);
    rcntrl_connect(&_rcntrl);
}

/******************************************
    server
 ******************************************/

static void server_create(struct server_t *rrs) {
    log_debug("creating server");
    struct sockaddr_in addr;
    uint16_t port = globals.port;
    int ret;

    rrs->rchannel = NULL;
    rrs->rid = NULL;
    rrs->base_addr = 0;
    rrs->rdma_key = 0;

    globals.rrs = rrs;

    clilst_init();

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    // address 0 - listen across all RDMA devices
    addr.sin_port = htons(port);
    inet_aton(globals.server, &addr.sin_addr);

    log_info("server %s", globals.server);
    log_info("listening on port %d.", port);
    log_info("num slabs %ld.", globals.num_slabs);

    rrs->rchannel = rdma_create_event_channel();
    assert(rrs->rchannel);
    ret = rdma_create_id(rrs->rchannel, &rrs->rid, NULL, RDMA_PS_TCP);
    assertz(ret);
    ret = rdma_bind_addr(rrs->rid, (struct sockaddr *)&addr);
    assertz(ret);

    build_context(rrs->rid->verbs);
    server_export_memory(rrs, globals.num_slabs, RDMA_SERVER_SLAB_SIZE);

    ret = rdma_listen(rrs->rid, 10); /* backlog=10 is arbitrary */
    assertz(ret);

    port = ntohs(rdma_get_src_port(rrs->rid));

    connect2rcntrl(globals.rcntrl, globals.rcport);
}

static void server_destroy(struct server_t *rrs) {
    log_debug("destroying server");

    rdma_destroy_id(rrs->rid);
    rdma_destroy_event_channel(rrs->rchannel);

    // TODO: join cq poller thread - need to do check for events in a non-blocking
    // way
    //    if (s_ctx)
    //        pthread_join(s_ctx->cq_poller_thread, NULL);

    clilst_destroy();
}

static void server_run() {
    struct rdma_cm_event *event = NULL;
    struct server_t *rrs = (struct server_t *)xmalloc(sizeof(struct server_t));
    int ret;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    log_info("Pinning server to core %d", PIN_SERVER_CORE);
    CPU_SET(PIN_SERVER_CORE, &cpuset);
    ret = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    assertz(ret);

    server_create(rrs);

    while ((rdma_get_cm_event(rrs->rchannel, &event) == 0) && !aborted) {
        struct rdma_cm_event event_copy;

        log_debug("server loop");

        memcpy(&event_copy, event, sizeof(*event));
        rdma_ack_cm_event(event);

        process_event(&event_copy);
    }

    send_msg_server_rem(_rcntrl.rid->context);
    rcntrl_destroy(&_rcntrl);

    server_destroy(rrs);
}

/*************************************
    RDMA
 *************************************/

static void on_completion(struct ibv_wc *wc) {
    log_debug("completion..");
    struct connection *conn = (struct connection *)(uintptr_t)wc->wr_id;

    if (wc->status != IBV_WC_SUCCESS) {
        log_err("RDMA request failed with status %d: %s", wc->status,
                     ibv_wc_status_str(wc->status));
        return;
    }

    if (wc->opcode & IBV_WC_RECV) {
        switch (conn->recv_msg->type) {
            case MSG_DONE:
                log_info("received message DONE!");
                break;
            default:
                BUG();
        }
    } else {
        log_info("send completed successfully msg_type %d conn %p.",
                        conn->send_msg->type, conn);
    }
}

/* We habe a single completion poller for both the connection
to rcntrl and to app clients */
void *poll_cq(void *arg) {
    struct ibv_cq *cq;
    struct ibv_wc wc;
    void *ctx;
    int ret;

    pthread_setname_np(pthread_self(), "memsrvr_poll_cq");

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    log_info("Pinning completion poller to core %d", PIN_SERVER_POLLER_CORE);
    CPU_SET(PIN_SERVER_POLLER_CORE, &cpuset);
    ret = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    assertz(ret);

    while (!ibv_get_cq_event(s_ctx->comp_channel, &cq, &ctx)) {
        ibv_ack_cq_events(cq, 1);
        ret = ibv_req_notify_cq(cq, 0);
        assertz(ret);
        while (ibv_poll_cq(cq, 1, &wc)) on_completion(&wc);
    }

    return NULL;
}

void register_memory(struct connection *conn) {
    conn->send_msg = xmalloc(sizeof(struct message));
    conn->recv_msg = xmalloc(sizeof(struct message));

    conn->send_mr = ibv_reg_mr(s_ctx->pd, conn->send_msg, 
        sizeof(struct message), IBV_ACCESS_LOCAL_WRITE);
    assert(conn->send_mr);

    conn->recv_mr = ibv_reg_mr(s_ctx->pd, conn->recv_msg, 
        sizeof(struct message), IBV_ACCESS_LOCAL_WRITE);
    assert(conn->recv_mr);
}

static void build_context(struct ibv_context *verbs) {
    int ret;
    if (s_ctx) {
        assert(s_ctx->ctx == verbs);
        return;
    }

    s_ctx = (struct context *)xmalloc(sizeof(struct context));
    assert(s_ctx);
    s_ctx->ctx = verbs;
    // assert(s_ctx->ctx);

    s_ctx->pd = ibv_alloc_pd(s_ctx->ctx);
    assert(s_ctx->pd);
       s_ctx->comp_channel = ibv_create_comp_channel(s_ctx->ctx);
    assert(s_ctx->comp_channel);
    s_ctx->cq = ibv_create_cq(s_ctx->ctx, 10, NULL, s_ctx->comp_channel, 0); /* cqe=10 is arbitrary */
    assert(s_ctx->cq);
    ret = ibv_req_notify_cq(s_ctx->cq, 0);
    assertz(ret);

    ret = pthread_create(&s_ctx->cq_poller_thread, NULL, poll_cq, NULL);
    assertz(ret);
}

void build_qp_attr(struct ibv_qp_init_attr *qp_attr) {
    memset(qp_attr, 0, sizeof(*qp_attr));

    qp_attr->send_cq = s_ctx->cq;
    qp_attr->recv_cq = s_ctx->cq;
    qp_attr->qp_type = IBV_QPT_RC;

    qp_attr->cap.max_send_wr = 10;
    qp_attr->cap.max_recv_wr = 10;
    qp_attr->cap.max_send_sge = 1;
    qp_attr->cap.max_recv_sge = 1;
}

void build_connection(struct rdma_cm_id *id) {
    struct connection *conn;
    struct ibv_qp_init_attr qp_attr;
    int ret;

    // build_context(id->verbs);
    build_qp_attr(&qp_attr);

    ret = rdma_create_qp(id, s_ctx->pd, &qp_attr);
    assertz(ret);

    id->context = conn = (struct connection *)xmalloc(sizeof(struct connection));
    conn->id = id;
    conn->qp = id->qp;

    conn->connected = 0;

    struct client_info_t *cli =
            (struct client_info_t *)xmalloc(sizeof(struct client_info_t));
    cli->lstptr = NULL;
    clilst_add(cli);
    conn->peer = (void *)cli;

    register_memory(conn);
    post_receives(conn);
}

int on_connect_request(struct rdma_cm_id *id) {
    struct rdma_conn_param cm_params;
    int ret;

    log_debug("received connection request");
    build_connection(id);
    build_params(&cm_params);
    ret = rdma_accept(id, &cm_params);
    assertz(ret);

    return 0;
}

int on_connection(struct rdma_cm_id *id) {
    log_info("connected.\n");
    struct connection *conn = (struct connection *)id->context;

    conn->connected = 1;

    return 0;
}

int on_disconnect(struct rdma_cm_id *id) {
    log_info("disconnected.\n");
    struct connection *conn = (struct connection *)id->context;

    conn->connected = 0;
    clilst_remove(conn->peer);
    destroy_connection(conn);
    return 0;
}

void process_event(struct rdma_cm_event *event) {
    int ret;
    log_debug("process_event\n");

    if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST)
        ret = on_connect_request(event->id);
    else if (event->event == RDMA_CM_EVENT_ESTABLISHED)
        ret = on_connection(event->id);
    else if (event->event == RDMA_CM_EVENT_DISCONNECTED)
        ret = on_disconnect(event->id);
    else
        BUG();
    assertz(ret);
}

/*********************************************
    main
 *********************************************/

void usage() {
    printf("Usage ./memserver [-s memserver-ip] [-p memserver-port] "
        "[-c rcntrl-ip] [-r rcntrl-port] [-n num-slabs]\n");
    printf("Default memserver address is %s\n", RDMA_SERVER_IP);
    printf("Default memserver port is %d\n", RDMA_SERVER_PORT);
    printf("Default rcntrl address is %s\n", RDMA_RACK_CNTRL_IP);
    printf("Default rcntrl port is %d\n", RDMA_RACK_CNTRL_PORT);
    printf("Default number of slabs %lu\n", RDMA_SERVER_NSLABS);
    printf("Slab size is %lu bytes\n", RDMA_SERVER_SLAB_SIZE);
    printf("Default values can be changed in config.h\n");
    printf("\n");
}

int main(int argc, char **argv) {
    int opt;
    register_signal_handler();

    strcpy(globals.server, RDMA_SERVER_IP);
    globals.port = RDMA_SERVER_PORT;
    strcpy(globals.rcntrl, RDMA_RACK_CNTRL_IP);
    globals.rcport = RDMA_RACK_CNTRL_PORT;
    globals.num_slabs = RDMA_SERVER_NSLABS;
    while ((opt = getopt(argc, argv, "hs:p:c:r:n:")) != -1) {
        switch (opt) {
            case 'h':
                usage();
                return 0;
            case 's':
                strcpy(globals.server, optarg);
                break;
            case 'p':
                globals.port = atoi(optarg);
                break;
            case 'c':
                strcpy(globals.rcntrl, optarg);
                break;
            case 'r':
                globals.rcport = atol(optarg);
                break;
            case 'n':
                globals.num_slabs = atoi(optarg);
                break;
        }
    }

    log_info("server started");
    server_run();
    log_info("server stopped");
    return 0;
}
