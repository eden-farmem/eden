/*
 * rdma.c - RDMA helper for remote memory (client-side)
 */

#include <execinfo.h>
#include "rmem/rdma.h"


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

void do_rdma_op(request_t *req, bool signal_completion) {
    struct ibv_send_wr wr, *bad_wr = NULL;
    struct ibv_sge sge;

    memset(&sge, 0, sizeof(sge));
    sge.addr = req->local_addr;
    sge.length = req->size;
    sge.lkey = req->lkey;

    memset(&wr, 0, sizeof(wr));
    wr.wr_id = (uintptr_t) req;      /* TODO: Is sending pointer safe? */
    wr.opcode = (req->mode == M_WRITE) ? IBV_WR_RDMA_WRITE : IBV_WR_RDMA_READ;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.send_flags = ((signal_completion) ? IBV_SEND_SIGNALED : 0);
    wr.wr.rdma.remote_addr = req->remote_addr;
    wr.wr.rdma.rkey = req->rkey;

    int r = ibv_post_send(req->conn->qp, &wr, &bad_wr);
    if (r != 0) {
        log_err("ibv_post_send new op=%d errno=%d\n", wr.opcode, r);
        BUG();
    }
}

void do_rdma_op_linked(request_t *reqs, unsigned n_reqs, bool signal_completion)
{
    // This function call is not thread safe at all!
    struct ibv_send_wr *bad_wr = NULL;

    static struct ibv_send_wr wrs[MAX_LINKED_WRS];
    static struct ibv_sge sges[MAX_LINKED_WRS];

    assert(n_reqs <= MAX_LINKED_WRS);
    assert(n_reqs > 0);

    // Generate all WRs.
    for (unsigned i = 0; i < n_reqs; i++) {
        memset(&sges[i], 0, sizeof(sges[i]));
        sges[i].addr = reqs[i].local_addr;
        sges[i].length = reqs[i].size;
        sges[i].lkey = reqs[i].lkey;

        memset(&wrs[i], 0, sizeof(wrs[i]));
        wrs[i].wr_id = (uintptr_t) &reqs[i];
        wrs[i].opcode =
                (reqs[i].mode == M_WRITE) ? IBV_WR_RDMA_WRITE : IBV_WR_RDMA_READ;
        wrs[i].sg_list = &sges[i];
        wrs[i].num_sge = 1;
        wrs[i].send_flags =
                ((signal_completion && i == (n_reqs - 1)) ? IBV_SEND_SIGNALED : 0);
        wrs[i].wr.rdma.remote_addr = reqs[i].remote_addr;
        wrs[i].wr.rdma.rkey = reqs[i].rkey;
    }

    // Link all requests.
    for (unsigned i = 0; i < (n_reqs - 1); i++) {
        wrs[i].next = &wrs[i + 1];
    }

    int r = ibv_post_send(reqs[0].conn->qp, &wrs[0], &bad_wr);
    if (r != 0) {
        log_err("ibv_post_send errno=%d\n", r);
        BUG();
    }
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
