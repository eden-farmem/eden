/*
 * rdma.h - RDMA helper for remote memory (server-side)
 * TODO: Consolidate this with runtime/rdma.h
 */

#ifndef __RDMA_H__
#define __RDMA_H__

#include <infiniband/verbs.h>
#include <netdb.h>
#include <rdma/rdma_cma.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include "rmem/config.h"
#include "rmem/rdma_common.h"
#include "rmem/region.h"

/**
 * Common context
 */
struct context {
    struct ibv_context *ctx;
    struct ibv_pd *pd;
    struct ibv_cq *cq_recv;
    struct ibv_cq *cq_send;
    struct ibv_cq *cq;
    struct ibv_comp_channel *comp_channel;
    pthread_t cq_poller_thread;
};

struct server_conn_t {
    char ip[36];
    int port;
    int id;
    int status;
    uint64_t rdmakey;
    uint64_t size;
    struct rdma_event_channel *rchannel;
    struct rdma_cm_id *rid;

    SLIST_ENTRY(server_conn_t) link;
};

struct connection {
    struct rdma_cm_id *id;
    struct ibv_qp *qp;

    void *peer;
    volatile int connected;

    struct ibv_mr *recv_mr;
    struct ibv_mr *send_mr;
    struct message *recv_msg;
    struct message *send_msg;
    struct region_t* reg;
};

void build_params(struct rdma_conn_param *params);
void destroy_connection(struct connection *conn);
void post_receives(struct connection *conn);
void send_message(struct connection *conn);

#endif    // __RDMA_H__
