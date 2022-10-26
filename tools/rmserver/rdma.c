/*
 * rdma.c - RDMA helper for remote memory (server-side)
 * TODO: Consolidate this with runtime/rmem/rdma.c
 */

#include <execinfo.h>
#include "rmem/rdma_common.h"
#include "rdma.h"

void build_params(struct rdma_conn_param *params) {
    memset(params, 0, sizeof(*params));
    params->initiator_depth = params->responder_resources = 1;
    params->rnr_retry_count = 7; /* infinite retry */
}

void destroy_connection(struct connection *conn) {
    rdma_destroy_qp(conn->id);

    ibv_dereg_mr(conn->send_mr);
    ibv_dereg_mr(conn->recv_mr);

    free(conn->send_msg);
    free(conn->recv_msg);

    rdma_destroy_id(conn->id);

    free(conn);
}

void post_receives(struct connection *conn) {
    struct ibv_recv_wr wr, *bad_wr = NULL;
    struct ibv_sge sge;

    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)conn->recv_msg;
    sge.length = sizeof(struct message);
    sge.lkey = conn->recv_mr->lkey;

    memset(&wr, 0, sizeof(wr));
    wr.wr_id = (uintptr_t)conn;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    int r = ibv_post_recv(conn->qp, &wr, &bad_wr);
    if (r != 0) {
        log_err("ibv_post_recv errno=%d\n", r);
        BUG();
    }
}

void send_message(struct connection *conn) {
    struct ibv_send_wr wr, *bad_wr = NULL;
    struct ibv_sge sge;

    memset(&wr, 0, sizeof(wr));

    wr.wr_id = (uintptr_t)conn;
    wr.opcode = IBV_WR_SEND;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.send_flags = IBV_SEND_SIGNALED;

    sge.addr = (uintptr_t)conn->send_msg;
    sge.length = sizeof(struct message);
    sge.lkey = conn->send_mr->lkey;

    while (!conn->connected);

    int r = ibv_post_send(conn->qp, &wr, &bad_wr);
    if (r != 0) {
        log_err("ibv_post_send errno=%d\n", r);
        BUG();
    }
}
