/*
 * rdma.h - RDMA helper for remote memory (client-side)
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
    struct ibv_comp_channel *cc;
};

/**
 * State for a single connection
 */
struct server_conn_t;
struct connection {
    /* metadata */
    struct server_conn_t* server;
    uint8_t datapath;
    uint8_t use_global_cq;
    uint8_t one_send_recv_cq;

    /* status */
    volatile int connected;
    
    /* rdma connection state */
    struct rdma_cm_id *id;
    struct rdma_event_channel *chan;
    struct ibv_qp *qp;
    /* completion queue state */
    struct ibv_cq *cq_recv;
    struct ibv_cq *cq_send;
    struct ibv_comp_channel *cc;
    /* memory buf */
    struct ibv_mr *recv_mr;
    struct ibv_mr *send_mr;
    struct message *recv_msg;
    struct message *send_msg;

    /* placeholder for region association during region add/remove 
     * vestige of bad design from kona. TODO: fix it */
    struct region_t* reg;
} __aligned(CACHE_LINE_SIZE);

/**
 * A server connection that is also currently tied to a single
 * region. TODO: we should decouple them later.
 */
struct server_conn_t {
    char ip[36];
    int port;
    int id;
    int status;
    uint64_t rdmakey;
    uint64_t size;

    int num_dp;
    struct connection cp;   /* control path */
    struct connection dp[MAX_QPS_PER_REGION];   /* data path */

    struct region_t* reg;   /* backref to general */
    SLIST_ENTRY(server_conn_t) link;
};

struct __request_t {
    volatile int busy;
    volatile int ready;
    struct connection *conn;
    struct server_conn_t *server;
    unsigned long local_addr;
    unsigned long remote_addr;
    unsigned int lkey;
    unsigned int rkey;
    unsigned long size;
    int fd;
    rw_mode_t mode;
    rw_mode_t fault_mode;
    struct region_t *mr;
    int index;
    unsigned long vaddr;
};

typedef struct __request_t request_t;

void build_params(struct rdma_conn_param *params);
void destroy_connection(struct connection *conn);
void post_receives(struct connection *conn);
void send_message(struct connection *conn);
void do_rdma_op(request_t *req, bool signal_completion);
void do_rdma_op_linked(request_t *reqs, unsigned n_reqs, bool signal_completion);

#endif    // __RDMA_H__
