// Copyright © 2018-2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

/*****************************************************************************
    Rack controller
    Rack-level memory allocation and memory server list management
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
#include <stdatomic.h>
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
#include "base/assert.h"
#include "rmem/rdma.h"

static struct context *s_ctx = NULL;
static atomic_int server_id = ATOMIC_VAR_INIT(1);

static volatile bool aborted = false;

struct client_list_t;
struct server_list_t;

struct {
    char ip[200];
    int port;
    char server_map[MAX_SERVERS + 2][210];
} globals;

struct rcntrl_t {
    struct rdma_cm_id *rid;
    struct rdma_event_channel *rchannel;
};

struct server_info_t {
    /* pointer to active servers list */
    struct server_list_t *lstptr;
    char ip[200];
    int port;
    uint64_t rdmakey;
    int nslabs;
    int available_slabs;
    void *memaddr;
    int id;
    int *slab_availability_flag;
};

struct server_list_t {
    struct server_info_t *server;
    struct server_list_t *next;
    struct server_list_t *prev;
} * _servlst_head, *_servlst_tail;

struct client_info_t {
    /* pointer to active client list */
    struct client_list_t *lstptr;
    struct server_info_t *server;
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

/**********************************
    bitmap management
 ************************************/

#define BITMAP_MASK 0x1f
#define BITMAP_SHIFT 5

static void init_bitmap(struct server_info_t *server, int size) {
    size = ((align_up(size, 1 << BITMAP_SHIFT)) >> BITMAP_SHIFT);
    log_info("bitmap size: %d", size);
    server->slab_availability_flag = (int *)calloc(1, size * sizeof(int));
    // memset(server->slab_availability_flag, 0x00, size*sizeof(int));
}

static void set_bit(int *bitmap, int bit) {
    bitmap[bit >> BITMAP_SHIFT] |= 1 << (bit & BITMAP_MASK);
}

static void clear_bit(int *bitmap, int bit) {
    bitmap[bit >> BITMAP_SHIFT] &= ~1 << (bit & BITMAP_MASK);
}

static int get_bit(int *bitmap, int bit) {
    return ((bitmap[bit >> BITMAP_SHIFT] & (1 << (bit & BITMAP_MASK))) != 0);
}

/************************************
    server list management
 ***********************************/

static void servlst_init() {
    _servlst_head = (struct server_list_t *)xmalloc(sizeof(struct server_list_t));
    _servlst_tail = (struct server_list_t *)xmalloc(sizeof(struct server_list_t));
    _servlst_head->server = NULL;
    _servlst_tail->server = NULL;
    _servlst_head->next = _servlst_tail;
    _servlst_head->prev = NULL;
    _servlst_tail->next = NULL;
    _servlst_tail->prev = _servlst_head;
}

struct server_info_t *find_server_by_id(int id) {
    struct server_list_t *serv = _servlst_head->next;

    while (serv != _servlst_tail) {
        if (serv->server->id == id) {
            return serv->server;
        }
        serv = serv->next;
    }
    return NULL;
}

static void get_server_id(struct server_info_t *server) {
    int i;
    char hash[210];
    log_debug("current server id:%d", server_id);
    sprintf(hash, "%s:%d", server->ip, server->port);
    for (i = 1; i < MAX_SERVERS && i < server_id; i++) {
        if (globals.server_map[i] && strcmp(globals.server_map[i], hash) == 0) {
            server->id = i;
            return;
        }
    }
    server->id = atomic_fetch_add_explicit(&server_id, 1, memory_order_acquire);
    log_debug("server id set to: %d", server->id);
    sprintf(globals.server_map[server->id], "%s:%d", server->ip, server->port);
    return;
}

static int is_duplicate_server(struct server_info_t *server) {
    if (server->ip == NULL || !server->port) {
        log_err("invalid server ip or port");
        return -1;
    }

    struct server_list_t *serv = _servlst_head->next;

    while (serv != _servlst_tail) {
        if (strcmp(serv->server->ip, server->ip) == 0 &&
                serv->server->port == server->port) {
            server->lstptr = serv->server->lstptr;
            server->id = serv->server->id;
            serv->server = server;
            log_info("server already exists with id: %d", server->id);
            return 1;
        }
        serv = serv->next;
    }
    return 0;
}

static void servlst_add(struct server_info_t *serv) {
    log_debug("servlst adding server %p link %p head %p tail %p", serv,
                     serv->lstptr, _servlst_head, _servlst_tail);

    if (is_duplicate_server(serv) == 0) {
        struct server_list_t *newserv =
                (struct server_list_t *)xmalloc(sizeof(struct server_list_t));
        serv->lstptr = newserv;
        newserv->server = serv;
        newserv->next = _servlst_head->next;
        newserv->prev = _servlst_head;
        newserv->next->prev = newserv;
        _servlst_head->next = newserv;
    }
}

static void servlst_remove(struct server_info_t *serv) {
    assert(serv);

    log_debug("servlst remove server %p link %p head %p tail %p", serv,
                     serv->lstptr, _servlst_head, _servlst_tail);

    struct server_list_t *oldserv = serv->lstptr;

    assert(oldserv != _servlst_head);
    assert(oldserv != _servlst_tail);

    oldserv->prev->next = oldserv->next;
    oldserv->next->prev = oldserv->prev;

    free(oldserv->server);
    free(oldserv);
}

static void servlst_destroy() {
    log_debug("servlst destroy");
    struct server_list_t *serv = _servlst_head->next;
    struct server_list_t *oldserv = NULL;

    while (serv != _servlst_tail) {
        oldserv = serv;
        serv = serv->next;
        servlst_remove(oldserv->server);
    }

    log_debug("freeing head %p and tail %p", _servlst_head, _servlst_tail);
    free(_servlst_head);
    free(_servlst_tail);
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

/******************************************
    controller
 ******************************************/

static void rcntrl_create(struct rcntrl_t *rrs) {
    struct sockaddr_in addr;
    uint16_t port = globals.port;
	int ret;

    rrs->rchannel = NULL;
    rrs->rid = NULL;

    servlst_init();
    clilst_init();

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    // address 0 - listen across all RDMA devices
    addr.sin_port = htons(port);
    inet_aton(globals.ip, &addr.sin_addr);

	rrs->rchannel = rdma_create_event_channel();
	assert(rrs->rchannel);
    ret = rdma_create_id(rrs->rchannel, &(rrs->rid), NULL, RDMA_PS_TCP);
	assertz(ret);
    ret = rdma_bind_addr(rrs->rid, (struct sockaddr *)&addr);
	assertz(ret);

    build_context(rrs->rid->verbs);

    ret = rdma_listen(rrs->rid, 10); /* backlog=10 is arbitrary */
    assertz(ret);

    port = ntohs(rdma_get_src_port(rrs->rid));
    log_info("rcntrl %s listening on port %d.", globals.ip, port);
}

static void rcntrl_destroy(struct rcntrl_t *rrs) {
    log_debug("destroying rcntrl");

    rdma_destroy_id(rrs->rid);
    rdma_destroy_event_channel(rrs->rchannel);

    // TODO: join cq poller thread - need to do check for events in a non-blocking way
	// if (s_ctx)
	// 	pthread_join(s_ctx->cq_poller_thread, NULL);
    servlst_destroy();
    clilst_destroy();
}

static void rcntrl_run() {
    struct rdma_cm_event *event = NULL;
    struct rcntrl_t *rrs = (struct rcntrl_t *)xmalloc(sizeof(struct rcntrl_t));
	int ret;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    log_info("Pinning server to core %d", PIN_RACK_CNTRL_CORE);
    CPU_SET(PIN_RACK_CNTRL_CORE, &cpuset);
    ret = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    assertz(ret);

    log_debug("creating rcntrl");
    rcntrl_create(rrs);

    while ((rdma_get_cm_event(rrs->rchannel, &event) == 0) && !aborted) {
        struct rdma_cm_event event_copy;
        log_debug("rcntrl loop");
        memcpy(&event_copy, event, sizeof(*event));
        rdma_ack_cm_event(event);
        process_event(&event_copy);
    }

    log_debug("destroying rcntrl");
    rcntrl_destroy(rrs);
}

/********************************************
                Remote memory management
 *********************************************/

int is_slab_available(struct server_info_t *serv, int slab) {
    if (slab > serv->nslabs) return 0;
    return (get_bit(serv->slab_availability_flag, slab) == 0);
}

int find_available_slabs(struct server_info_t *serv) {
    int slab = 0;
    while ((slab < serv->nslabs) && (!is_slab_available(serv, slab))) {
        ++slab;
    }
    assert(slab < serv->nslabs);
    return slab;
}

void *addr_from_slab(struct server_info_t *server, int slab) {
    if (server == NULL || slab < 0 || slab >= server->nslabs) return NULL;
    return server->memaddr + slab * RDMA_SERVER_SLAB_SIZE;
}

int slab_from_addr(struct server_info_t *server, uint64_t addr) {
    if (server ==
            NULL)    // || addr < (uint64_t) server->memaddr || addr > (uint64_t)
                         // server->memaddr + server->nslabs*RDMA_SERVER_SLAB_SIZE)
        return -1;
    return (int)((addr - (uint64_t)server->memaddr) / RDMA_SERVER_SLAB_SIZE);
}

// @return: the number of allocated slabs in one server
int alloc_next_slabs(int requested_slabs, struct server_info_t **server,
                                         uint64_t *slab_addr) {
    int granted_slabs = 0;
    int next_slab = -1;
    struct server_info_t *cserver = NULL;
    struct server_list_t *serv = _servlst_head->next;

    while ((serv != _servlst_tail) && (granted_slabs == 0)) {
        cserver = serv->server;
        if (cserver->available_slabs > 0) {
            next_slab = find_available_slabs(cserver);
            assert(next_slab != -1);
            *slab_addr = (uint64_t)addr_from_slab(cserver, next_slab);
            granted_slabs = (cserver->available_slabs - next_slab >= requested_slabs)
                                                    ? requested_slabs
                                                    : (cserver->nslabs - next_slab);
            *server = cserver;
            log_debug("slab:%d, granted:%d, addr:%p", next_slab, granted_slabs,
                             (void *)slab_addr);
            for (int i = 0; i < granted_slabs; i++)
                set_bit(cserver->slab_availability_flag, next_slab + i);
            cserver->available_slabs -= granted_slabs;
            return granted_slabs;
        }
        serv = serv->next;
    }

    log_err("rack is out of memory!");
    return granted_slabs;
}

/**************************************************
    Protocol msgs
 **************************************************/

static void send_msg_done(struct connection *conn) {
    log_debug("send_msg_done");

    conn->send_msg->type = MSG_DONE;
    conn->send_msg->data.addr = NULL;

    send_message(conn);
}

static void on_recv_server_add(struct connection *conn) {
    log_info("on_recv_server_add");

    struct client_info_t *cli = (struct client_info_t *)conn->peer;
    assert(cli->server == NULL);
    struct server_info_t *server =
            (struct server_info_t *)xmalloc(sizeof(struct server_info_t));
    log_info("adding server %p (client id %p)", server, cli);

    server->lstptr = NULL;
    strcpy(server->ip, conn->recv_msg->data.ip);
    server->port = conn->recv_msg->data.port;
    server->nslabs = conn->recv_msg->data.nslabs;
    server->available_slabs = server->nslabs;
    server->memaddr = conn->recv_msg->data.addr;
    server->rdmakey = conn->recv_msg->data.rdmakey;
    get_server_id(server);
    init_bitmap(server, server->available_slabs);
    cli->server = server;

    /* add to list of servers */
    servlst_add(server);
    log_info(
            "server id: %d, ip: %s, port: %d, available slabs: %d, memaddr: %p, "
            "flag: %p, global_map: %s",
            server->id, server->ip, server->port, server->available_slabs,
            server->memaddr, &server->slab_availability_flag,
            globals.server_map[server->id]);

    post_receives(conn);

    send_msg_done(conn);
}

static void on_recv_server_rem(struct connection *conn) {
    log_debug("on_recv_server_rem");

    struct client_info_t *cli = (struct client_info_t *)conn->peer;
    struct server_info_t *server = cli->server;

    server->nslabs = 0;
    server->available_slabs = 0;
    // cli->server = NULL;
    servlst_remove(server);

    post_receives(conn);

    send_msg_done(conn);
}

static void on_recv_slabs_add(struct connection *conn) {
    log_debug("on_recv_slab_add");

    struct client_info_t *client = (struct client_info_t *)conn->peer;
    unsigned long slab_addr;

    // find and allocate next available slabs
    int nrequested_slabs = conn->recv_msg->data.nslabs;

    while (nrequested_slabs > 0) {
        struct server_info_t *server;
        int granted_slabs = alloc_next_slabs(nrequested_slabs, &server, &slab_addr);

        if (granted_slabs == 0) break;
        conn->send_msg->type = MSG_SLAB_ADD_PARTIAL;
        strcpy(conn->send_msg->data.ip, server->ip);
        conn->send_msg->data.port = server->port;
        conn->send_msg->data.id = server->id;
        conn->send_msg->data.rdmakey = server->rdmakey;
        conn->send_msg->data.nslabs = granted_slabs;
        conn->send_msg->data.addr = (void *)slab_addr;
        client->server = server;
        post_receives(conn);
        send_message(conn);
        log_debug("sent slab info. id:%d, addr:%p, nslabs:%d",
                         conn->send_msg->data.id, conn->send_msg->data.addr,
                         conn->send_msg->data.nslabs);
        nrequested_slabs -= granted_slabs;
        usleep(10);
    }
    conn->send_msg->type = MSG_DONE_SLAB_ADD;
    conn->send_msg->data.addr = NULL;
    post_receives(conn);
    send_message(conn);
}

static void on_recv_slabs_rem(struct connection *conn) {
    log_debug("on_recv_slab_rem");

    // struct client_info_t *client = (struct client_info_t *)conn->peer;

    int id = conn->recv_msg->data.id;
    int nslabs = conn->recv_msg->data.nslabs;
    void *addr = conn->recv_msg->data.addr;

    struct server_info_t *server = find_server_by_id(id);
    if (server == NULL) goto out;
    int slab = slab_from_addr(server, (unsigned long)addr);
    int i;
    log_debug("slab:%d, nslabs:%d, addr:%p", slab, nslabs, addr);
    for (i = 0; i < nslabs; i++) {
        clear_bit(server->slab_availability_flag, slab + i);
        server->available_slabs++;
    }
out:
    post_receives(conn);
    send_msg_done(conn);
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
            case MSG_SERVER_ADD:
                on_recv_server_add(conn);
                break;
            case MSG_SERVER_REM:
                on_recv_server_rem(conn);
                break;
            case MSG_SLAB_ADD:
                on_recv_slabs_add(conn);
                break;
            case MSG_SLAB_REM:
                on_recv_slabs_rem(conn);
            default:
                BUG();
        }
    } else {
        log_info("send completed successfully msg_type %d conn %p.",
                        conn->send_msg->type, conn);
    }
}

void *poll_cq(void *arg) {
    struct ibv_cq *cq;
    struct ibv_wc wc;
    void *ctx;
	int ret;

    pthread_setname_np(pthread_self(), "rcntrl_poll_cq");

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    log_info("Pinning completion poller to core %d", PIN_RACK_CNTRL_POLLER_CORE);
    CPU_SET(PIN_RACK_CNTRL_POLLER_CORE, &cpuset);
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

    conn->send_mr = ibv_reg_mr(s_ctx->pd, conn->send_msg, sizeof(struct message),
        IBV_ACCESS_LOCAL_WRITE);
    assert(conn->send_mr);

    conn->recv_mr = ibv_reg_mr(s_ctx->pd, conn->recv_msg, sizeof(struct message),
        IBV_ACCESS_LOCAL_WRITE);
    assert(conn->recv_mr);
}

static void build_context(struct ibv_context *verbs) {
	int ret;
    if (s_ctx) {
        assert(s_ctx->ctx == verbs);
        return;
    }

    s_ctx = (struct context *)xmalloc(sizeof(struct context));
    s_ctx->ctx = verbs;
    assert(s_ctx->ctx);

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
    struct connection *conn = (struct connection *)id->context;
    struct client_info_t *cli =
            (struct client_info_t *)xmalloc(sizeof(struct client_info_t));
    log_info("\nclient %p connected.", cli);
    cli->lstptr = NULL;
    cli->server = NULL;
    conn->peer = (void *)cli;
    clilst_add(cli);

    conn->connected = 1;

    return 0;
}

int on_disconnect(struct rdma_cm_id *id) {
    struct connection *conn = (struct connection *)id->context;
    struct client_info_t *cli = conn->peer;
    log_info("client (server=%d)    %p disconnected.\n", !(cli->server == NULL),
                    cli);

    conn->connected = 0;

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
 **********************************************/

void usage() {
    printf("Usage ./rcntrl [-s rcntrl-ip] [-p rcntrl-port]\n");
    printf("Default controller address is %s (config.h)\n", RDMA_RACK_CNTRL_IP);
    printf("Default port is %d (config.h)\n", RDMA_RACK_CNTRL_PORT);
    printf("\n");
}

int main(int argc, char **argv) {
    int opt;
    register_signal_handler();

    strcpy(globals.ip, RDMA_RACK_CNTRL_IP);
    globals.port = RDMA_RACK_CNTRL_PORT;

    while ((opt = getopt(argc, argv, "hs:p:")) != -1) {
        switch (opt) {
            case 'h':
                usage();
                return 0;
            case 's':
                strcpy(globals.ip, optarg);
                break;
            case 'p':
                globals.port = atoi(optarg);
                break;
        }
    }

    log_info("rcntrl started");
    rcntrl_run();
    log_info("rcntrl stopped");
    return 0;
}
