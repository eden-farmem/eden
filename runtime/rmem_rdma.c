/*
 * rmem_rdma.c - RDMA remote memory backend
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <netdb.h>
#include <sys/mman.h>
#include <sys/queue.h>

#include "rmem/backend.h"
#include "rmem/rdma.h"
#include "defs.h"

/*TODO: these need to be revisited after per-core QPs/CQs */
#define MAX_CONCURRENT_R_REQS 256
#define MAX_CONCURRENT_W_REQS 256
#define CQ_RECV_SIZE 10
#define CQ_SEND_SIZE (MAX_CONCURRENT_R_REQS + MAX_CONCURRENT_W_REQS)

/* global state */
struct server_conn_t* servers[MAX_SERVERS + 1];
SLIST_HEAD(servers_listhead, server_conn_t);
struct servers_listhead servers_list;
static struct context *s_ctx = NULL;
__thread struct ibv_wc wc[NUM_POLL_CQ];
bool ready_for_poll = false;

// request_t _reqs[MAX_CONCURRENT_R_REQS];
// request_t *_reqsw;

static int on_route_resolved(struct rdma_cm_id *id);
static int on_completion(struct ibv_wc *wc, struct region_t *reg,
    enum ibv_wc_opcode opcode, int msgtype);
static int connect2server(int index);

/* recv cq is sync */
static void wait_one_completion(struct region_t *reg, enum ibv_wc_opcode opcode,
        int msgtype) {
    struct ibv_cq *cq;
    struct ibv_wc wc;
    int ret = 0;
    log_debug("wait one completion");

    assert(msgtype < NUM_MSG_TYPE);

    // struct context ctx;
    // ret = ibv_get_cq_event(s_ctx->comp_channel, &cq, (void **) &ctx));
    // assertz(ret);
    // ibv_ack_cq_events(cq, 1);
    // ret = ibv_req_notify_cq(cq, 0);
    // assertz(ret);

    cq = s_ctx->cq_recv;
    while (1) {
        if (ibv_poll_cq(cq, 1, &wc)) {
            ret = on_completion(&wc, reg, opcode, msgtype);
            if (msgtype != MSG_DONE_SLAB_ADD || (msgtype == MSG_DONE_SLAB_ADD && ret))
                break;
        }
    }
}

void on_recv_done_slab_add(struct connection *conn, struct region_t *reg) {
    int server_index = conn->recv_msg->data.id;
    struct server_conn_t *server = servers[server_index];
    strcpy(server->ip, conn->recv_msg->data.ip);
    server->port = conn->recv_msg->data.port;
    server->id = server_index;
    server->rdmakey = conn->recv_msg->data.rdmakey;
    server->size = ((unsigned long)conn->recv_msg->data.nslabs) * RDMA_SERVER_SLAB_SIZE;
    server->status = (server->status == CONNECTED ? CONNECTED : DISCONNECTED);
    reg->remote_addr = (unsigned long)conn->recv_msg->data.addr;
    reg->server = server;
    // TODO(irina): This should actually be align_down....
    reg->size = align_up(reg->server->size, PAGE_SIZE);
    log_info("region server size: %ld, region size: %ld", reg->server->size, reg->size);
    
    int r = register_memory_region(reg, 1);
    assertz(r);
    assert(reg->addr);
    log_info("granted slabs:%d, server size: %ld", conn->recv_msg->data.nslabs,
        server->size);
    log_debug("%s:slab added on server:%s, port:%d, id:%d, at address %p",
        __func__, server->ip, server->port, server->id, (void *)reg->remote_addr);

    if (reg->server->status == DISCONNECTED) {
        int ret = connect2server(reg->server->id);
        assertz(ret);
    }
}

void on_recv_done(struct connection *conn, struct region_t *reg) {
    log_debug("received done! %p", conn->recv_msg->data.addr);
}

void poller_on_completion(struct ibv_wc *wc) {
    struct connection *conn = (struct connection *)(uintptr_t)wc->wr_id;
    enum ibv_wc_opcode opcode = wc->opcode;

    if (wc->status != IBV_WC_SUCCESS) {
        log_err("RDMA request failed with status %d: %s", wc->status,
            ibv_wc_status_str(wc->status));
        fflush(stdout);
        BUG();
    }

    if (opcode & IBV_WC_RECV) {
        int msgtype = conn->recv_msg->type;
        struct region_t *reg = conn->reg;

        switch (msgtype) {
            case MSG_DONE_SLAB_ADD:
                on_recv_done_slab_add(conn, reg);
                break;
            case MSG_DONE:
                on_recv_done(conn, reg);
                break;
            default:
                BUG();
        }
    } else if (opcode == IBV_WC_SEND) {
        // assert(conn->send_msg->type == msgtype);
        log_debug("send completed successfully on conn %p msg %d.", conn,
            conn->send_msg->type);
    } else if (opcode == IBV_WC_RDMA_READ) {
        BUG();
    } else {
        assert(opcode == IBV_WC_RDMA_WRITE);
        BUG();
    }
}

static int on_completion(struct ibv_wc *wc, struct region_t *reg, 
        enum ibv_wc_opcode opcode, int msgtype) {
    struct connection *conn = (struct connection *)(uintptr_t)wc->wr_id;
    if (wc->status != IBV_WC_SUCCESS) {
        log_err("RDMA request failed with status %d: %s", wc->status,
            ibv_wc_status_str(wc->status));
    }
    assert(wc->status == IBV_WC_SUCCESS);
    int received_message =
        (wc->opcode & IBV_WC_RECV) ? conn->recv_msg->type : conn->send_msg->type;
    log_debug("expected opcode: %d, recv opcode: %d, expected msg type: %d, "
        "recv msg type: %d", opcode, wc->opcode, msgtype, received_message);

    if (wc->opcode & IBV_WC_RECV) {
        assert(opcode == IBV_WC_RECV);
        // assert(conn->recv_msg->type == msgtype);
        switch (conn->recv_msg->type) {
            case MSG_DONE_SLAB_ADD:
                break;
            case MSG_SLAB_ADD_PARTIAL:
                on_recv_done_slab_add(conn, reg);
                break;
            case MSG_DONE:
                on_recv_done(conn, reg);
                break;
            default:
                BUG();
        }
        if (msgtype == MSG_DONE_SLAB_ADD && received_message != msgtype)
            post_receives(conn);
        log_debug("going to return %d", (received_message == msgtype));
        return (received_message == msgtype);
    } else {
        if (opcode == IBV_WC_SEND) {
            assert(conn->send_msg->type == msgtype);
            log_debug("send completed successfully on conn %p msg %d.", conn,
                received_message);
        } else {
            assert(opcode == IBV_WC_RDMA_READ || opcode == IBV_WC_RDMA_WRITE);
            log_debug("RDMA READ/WRITE completed successfully");
        }
        // log_debug("going to return %d", (received_message == msgtype));
        return 1;    //(received_message == msgtype);
    }
}

void register_memory(struct connection *conn) {
    conn->send_msg = malloc(sizeof(struct message));
    assert(conn->send_msg);

    conn->recv_msg = malloc(sizeof(struct message));
    assert(conn->recv_msg);

    conn->send_mr = ibv_reg_mr(s_ctx->pd, conn->send_msg, 
        sizeof(struct message), IBV_ACCESS_LOCAL_WRITE);
    assert(conn->send_mr);

    conn->recv_mr = ibv_reg_mr(s_ctx->pd, conn->recv_msg, 
        sizeof(struct message), IBV_ACCESS_LOCAL_WRITE);
    assert(conn->recv_mr);
}

void build_context(struct ibv_context *verbs)
{
    if (s_ctx) {
        assert(s_ctx->ctx == verbs);
        return;
    }

    s_ctx = (struct context *) malloc(sizeof(struct context));
    assert(s_ctx);
    s_ctx->ctx = verbs;

    s_ctx->pd = ibv_alloc_pd(s_ctx->ctx);
	assert(s_ctx->pd);
   	s_ctx->comp_channel = ibv_create_comp_channel(s_ctx->ctx);
	assert(s_ctx->comp_channel);
    s_ctx->cq_send = ibv_create_cq(s_ctx->ctx, CQ_SEND_SIZE, NULL, s_ctx->comp_channel, 0);
    assert(s_ctx->cq_send);
    s_ctx->cq_recv = ibv_create_cq(s_ctx->ctx, CQ_RECV_SIZE, NULL, s_ctx->comp_channel, 0);
    assert(s_ctx->cq_recv);

    // polling, so we don't need the notification
    // int ret = ibv_req_notify_cq(s_ctx->cq, 0));
    // assertz(ret);

    mb();
    ready_for_poll = 1;
}

void build_qp_attr(struct ibv_qp_init_attr *qp_attr)
{
    memset(qp_attr, 0, sizeof(*qp_attr));

    qp_attr->send_cq = s_ctx->cq_send;
    qp_attr->recv_cq = s_ctx->cq_recv;
    qp_attr->qp_type = IBV_QPT_RC;

    qp_attr->cap.max_send_wr = CQ_SEND_SIZE;
    qp_attr->cap.max_recv_wr = CQ_RECV_SIZE;
    qp_attr->cap.max_send_sge = 1;
    qp_attr->cap.max_recv_sge = 1;
}

void build_connection(struct rdma_cm_id *id)
{
    struct connection *conn;
    struct ibv_qp_init_attr qp_attr;
    int ret;

    build_context(id->verbs);
    build_qp_attr(&qp_attr);

    ret = rdma_create_qp(id, s_ctx->pd, &qp_attr);
    assertz(ret);
    id->context = conn = (struct connection *)malloc(sizeof(struct connection));
    assert(conn);
    conn->id = id;
    conn->qp = id->qp;
    conn->peer = NULL;
    conn->connected = 0;

    register_memory(conn);
    post_receives(conn);
}

int on_addr_resolved(struct rdma_cm_id *id) {
    int ret;
    log_debug("address resolved.");
    build_connection(id);
    ret = rdma_resolve_route(id, TIMEOUT_IN_MS);
    assertz(ret);
    return 0;
}

int on_connection(struct rdma_cm_id *id) {
    log_debug("on connection");
    ((struct connection *)(id->context))->connected = 1;
    return 1;
}

int on_disconnect(struct rdma_cm_id *id) {
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
        r = on_connection(event->id);
    else if (event->event == RDMA_CM_EVENT_DISCONNECTED)
        r = on_disconnect(event->id);
    else {
        log_err("on_event: %d status: %d\n", event->event, event->status);
        log_err("Unknown event: is RDMA server running?");
        BUG();
    }
    return r;
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

/*************** server communication    ************************************/

void send_msg_slab_add(struct connection *conn, struct region_t *reg, int nslabs) 
{
    log_debug("sending MSG_SLAB_ADD");
    conn->send_msg->type = MSG_SLAB_ADD;
    conn->send_msg->data.nslabs = nslabs;
    conn->reg = reg;
    send_message(conn);
}

static void send_msg_slab_rem(struct connection *conn, struct region_t *reg) 
{
    log_debug("sending MSG_SLAB_REM");

    conn->send_msg->type = MSG_SLAB_REM;
    conn->reg = reg;
    conn->send_msg->data.nslabs = (int)(reg->server->size / RDMA_SERVER_SLAB_SIZE);
    conn->send_msg->data.id = reg->server->id;
    conn->send_msg->data.addr = (void *)reg->remote_addr;

    send_message(conn);
    // wait_one_completion(reg, IBV_WC_SEND, MSG_SLAB_REM);
    // wait_one_completion(reg, IBV_WC_RECV, MSG_DONE);
}

/**
 * Setup connections with the remote server (with one control connection and  
 * specified number of dataplane connections)
 */
void remote_client_create(struct server_conn_t *server, int dp_channels) 
{
    char portstr[10];
    struct addrinfo *addr = NULL;
    struct rdma_cm_event *event = NULL;
    int ret;

    /* get server address */
    assert(server != NULL);
    sprintf(portstr, "%d", server->port);
    log_info("client connection to server %s on port %s", server->ip, portstr);
    ret = getaddrinfo(server->ip, portstr, NULL, &addr);
    assertz(ret);

    /*  */
    server->rchannel = rdma_create_event_channel();
    assert(server->rchannel);
    ret = rdma_create_id(server->rchannel, &(server->rid), NULL, RDMA_PS_TCP);
    assertz(ret);
    ret = rdma_resolve_addr(server->rid, NULL, addr->ai_addr, TIMEOUT_IN_MS);
    assertz(ret);

    assert(addr != NULL);
    freeaddrinfo(addr);
    

    // initiate connection
    while (rdma_get_cm_event(server->rchannel, &event) == 0) {
        struct rdma_cm_event event_copy;
        memcpy(&event_copy, event, sizeof(*event));
        rdma_ack_cm_event(event);
        if (on_event(&event_copy)) break;
    }

    struct connection *conn = (struct connection *)server->rid->context;
    log_info("client connected to server %s on port %d, conn %p!", server->ip,
        server->port, conn);
    server->status = CONNECTED;
}

void remote_client_destroy(struct server_conn_t *server) {
    log_info("remote client destroy");
    rdma_destroy_event_channel(server->rchannel);
    server->status = DISCONNECTED;
}

// int remote_client_read(struct region_t *mr, unsigned long fault_addr,
//                                                rw_mode_t fault_mode, int fd, appfault_data_t* appdata) {
//     static int req_index = 0;
//     unsigned long remote_addr = mr->remote_addr + fault_addr - mr->addr;

//     //    assert(buf == local_rdma_mr->addr);
//     //    assert(size == RDMA_BUFFER_SIZE);

//     struct server_conn_t *server = mr->server;

//     struct connection *conn = (struct connection *)server->rid->context;

//     ++req_index;
//     if (req_index >= MAX_CONCURRENT_R_REQS) req_index = 0;
//     log_debug("will test if read request is busy..");
//     while (_reqs[req_index].busy != 0) {
//         PAUSE();
//     } 
//     log_debug("read request not busy, we can proceed for %lx: index=%d,appfault=%d", 
//         fault_addr, req_index, appdata != NULL);
//     _reqs[req_index].busy = 1;
//     _reqs[req_index].local_addr =
//             (unsigned long)read_buf + CHUNK_SIZE * req_index;
//     _reqs[req_index].remote_addr = remote_addr;
//     _reqs[req_index].lkey = read_rdma_mr->lkey;
//     _reqs[req_index].rkey = server->rdmakey;
//     _reqs[req_index].size = CHUNK_SIZE;
//     _reqs[req_index].mode = M_READ;
//     _reqs[req_index].fault_mode = fault_mode;
//     _reqs[req_index].mr = mr;
//     _reqs[req_index].index = req_index;
//     _reqs[req_index].vaddr = fault_addr;
//     _reqs[req_index].fd = fd;
//     _reqs[req_index].conn = conn;
//     _reqs[req_index].is_appfault = false;
//     if (appdata) {
//         _reqs[req_index].is_appfault = true;
//         _reqs[req_index].appdata = *appdata;
//     }

// #ifdef PERF_PROFILING
//     profile_start(PERF_PAGE_READ);
//     _reqs[req_index].start_cycles_low = v_PERF_PAGE_READ_start_cycles_low;
//     _reqs[req_index].start_cycles_high = v_PERF_PAGE_READ_start_cycles_high;
// #endif

//     log_debug("READ remote_addr %lx into local_addr %lx", remote_addr, fault_addr);
//     // do_rdma_op(&_reqs[req_index], true);
//     do_rdma_op2(_reqs, req_index, true, (char*)__func__);

// #ifdef PAGE_READ_NET_ACCOUNTING
//     unsigned long long page_read_time = time_ns(&ts_handler);
//     page_read_timestamps[req_index] = page_read_time;
// #endif

//     return req_index;
// }

// static void try_write(int index) {
//     if (_reqsw[index].ready) {
//         profile_start(PERF_RDMA_WRITE);

//         struct server_conn_t *server = _reqsw[index].server;
//         assert(server);
//         assert(server->rid);
//         struct connection *conn = (struct connection *)server->rid->context;
//         assert(conn);
//         assert(conn->qp);
//         log_debug(
//                 "writing remote buf at index %d from local_addr %p to remote_addr %p",
//                 index, (void *)_reqsw[index].local_addr,
//                 (void *)_reqsw[index].remote_addr);
//         _reqsw[index].conn = conn;
//         assert(write_rdma_mr);
//         _reqsw[index].lkey = write_rdma_mr->lkey;

//         _reqsw[index].ready = 0;

// #ifdef FLUSH_ENTIRE_PAGE
//         // do_rdma_op(&_reqsw[index], true);
//         do_rdma_op2(_reqsw, index, true, "try_write FLUSH_ENTIRE_PAGE");
// #else

//         unsigned long base_local = _reqsw[index].local_addr;
//         unsigned long base_remote = _reqsw[index].remote_addr;

// #ifndef RDMA_LINK_OPT
//         for (unsigned i = 0; i < NUM_CL_PER_PAGE; i++) {
//             unsigned long cl_offset = _reqsw[index].cl_writes[i].cl_offset;
//             size_t len = _reqsw[index].cl_writes[i].len;

//             // log_debug("Writing CL: local=%lx, len=%lu, cl_offset=%lu",    base_local,
//             // len, cl_offset);
//             assert(len <= CHUNK_SIZE);
//             assert((cl_offset + len) <= CHUNK_SIZE);

//             _reqsw[index].local_addr = base_local + cl_offset;
//             _reqsw[index].remote_addr = base_remote + cl_offset;
//             _reqsw[index].size = len;

//             if (i == (NUM_CL_PER_PAGE - 1) ||
//                     _reqsw[index].cl_writes[i + 1].len == ULONG_MAX) {
//                 // This is the last send command. We need completion signal from RDMA.
//                 // do_rdma_op(&_reqsw[index], true);
//                 do_rdma_op2(_reqsw, index, true, "try_write !RDMA_LINK_OPT1");
//                 break;

//             } else {
//                 // No completion signal needed from RDMA.
//                 // do_rdma_op(&_reqsw[index], false);
//                 do_rdma_op2(_reqsw, index, false, "try_write !RDMA_LINK_OPT1");
//             }
//         }
// #else

//         static request_t reqsw[MAX_LINKED_WRS];

//         for (unsigned i = 0; i < NUM_CL_PER_PAGE; i++) {
//             unsigned long cl_offset = _reqsw[index].cl_writes[i].cl_offset;
//             size_t len = _reqsw[index].cl_writes[i].len;

//             // log_debug("Writing CL: local=%lx, len=%lu, cl_offset=%lu",    base_local,
//             // len, cl_offset);
//             assert(len <= CHUNK_SIZE);
//             assert((cl_offset + len) <= CHUNK_SIZE);

//             memcpy((void *)&reqsw[i], (void *)&_reqsw[index], sizeof(_reqsw[index]));
//             reqsw[i].local_addr = base_local + cl_offset;
//             reqsw[i].remote_addr = base_remote + cl_offset;
//             reqsw[i].size = len;

//             if (i == (NUM_CL_PER_PAGE - 1) ||
//                     _reqsw[index].cl_writes[i + 1].len == ULONG_MAX) {
//                 // This is the last send command. Send a linked RDMA request
//                 do_rdma_op_linked(reqsw, i + 1, true);
//                 break;
//             }
//         }

// #endif    // RDMA_LINK_OPT
// #endif    // FLUSH_ENTIRE_PAGE

//         profile_stop(PERF_RDMA_WRITE);
//         accounting(_stats.n_net_page_out++);
//     }
// }

// void drain_write_reqs() {
//     /* TODO(irina): we need to maintain the order in which requests were submitted
//            Right now we don't use req_index, but we should */
//     static int req_index = 0;
//     int i;

//     // log_debug("drain write reqs from index %d", req_index);

//     for (i = req_index; i < MAX_CONCURRENT_W_REQS; i++) {
//         try_write(i);
//     }
//     for (i = 0; i < req_index; ++i) {
//         try_write(i);
//     }
// }

// int read_from_rdma_write_q(int fd, struct region_t *mr, unsigned long addr,
//                                                        rw_mode_t fault_mode, bool blocking, appfault_data_t* appdata) {
//     // Check if we can avoid RDMA read by using a value present in write buffer.

//     for (int i = 0; i < MAX_CONCURRENT_W_REQS; i++) {
//         if (_reqsw[i].ready && _reqsw[i].vaddr == addr) {
//             // We have a match. Try uffd_copy but do not block
// #ifdef READ_UFFD_MSGS_FREQUENT
//             read_uffd_msgs(true, false);
// #endif
//             int n_retries = 0;
//             int r = uffd_copy(fd, addr, _reqsw[i].local_addr,
//                                                 ((fault_mode == M_WRITE) ? 0 : UFFDIO_COPY_MODE_WP),
//                                                 blocking, &n_retries, false);
//             if (r == EAGAIN) {
//                 // This one has the latest data but we cannot block here either.
//                 // Let's push this fault back to queue and come back to it later on.
//                 log_debug("Unable to do uffd_copy right away, push RW fault to queue");
//                 fault_packet_t packet;
//                 packet.fd = fd;
//                 packet.mr = mr;
//                 packet.fault_addr = addr;
//                 packet.flags = ((fault_mode == M_WRITE) ? UFFD_PAGEFAULT_FLAG_WRITE : 0);
//                 packet.is_appfault = (appdata != NULL);
//                 if (appdata != NULL) 
//                     packet.appdata = *appdata;
//                 add_to_fault_queue(&packet);

//                 accounting(_stats.n_r_from_w_q_fail++);
//             }

//             if (r == 0) {
//                 accounting(_stats.n_r_from_w_q++);
//             }

//             return r;
//         }
//     }

//     return -1;
// }

// int remote_client_write(struct region_t *mr, unsigned long addr, size_t size,
//                                                 char *dirty_bitmap) {
//     log_debug("remote client write");
//     ///    pid_t pid = getpid();
//     unsigned long remote_addr = mr->remote_addr + addr - mr->addr;

// #ifdef RDMA_WRITE_IN_PFH
//     int req_index = -1;
//     while (1) {
//         for (int i = 0; i < MAX_CONCURRENT_W_REQS; ++i) {
//             if (!_reqsw[i].busy &&    // CAS(&_reqsw[i].busy, 0, 1)) {
//                                                             // atomic_compare_exchange_strong(&_reqsw[i].busy,
//                                                             // 0, 1)) {
//                     __sync_bool_compare_and_swap(&_reqsw[i].busy, 0, 1)) {
//                 req_index = i;
//                 break;
//             }
//         }
//         if (req_index != -1)
//             break;
//         else
//             pause;
//     }
// #else
//     static int req_index = 0;
//     ++req_index;
//     if (req_index >= MAX_CONCURRENT_W_REQS) req_index = 0;
//     log_debug("will test if write request is busy..");
//     while (_reqsw[req_index].busy != 0) {
//         PAUSE();
//     }
// #endif

//     request_t *volatile req = &_reqsw[req_index];
//     struct server_conn_t *server = mr->server;

//     unsigned long local_addr = (unsigned long)write_buf + CHUNK_SIZE * req_index;

//     assert(size == RDMA_BUFFER_SIZE);
//     log_debug("Will memcpy %p %p %ld: index=%d", (void *)local_addr, (void *)addr,
//                        size, req_index);
//     profile_start(PERF_EVICT_MEMCPY);
//     memcpy((void *)local_addr, (void *)addr, size);
//     profile_stop(PERF_EVICT_MEMCPY);

//     // Check if memcpy was consistent or did we get a WP fault on this page.
//     if (is_page_do_not_evict(mr, addr)) {
//         // Page was written while we were doing memcpy. Abort eviction!

//         // Return this RDMA queue entry.
//         _reqsw[req_index].busy = 0;
// #ifndef RDMA_WRITE_IN_PFH
//         // We want to reuse this queue entry next time
//         req_index--;
// #endif
//         log_debug("Page written while doing memcpy. Abort eviction");
//         return -1;
//     }

//     // We did memcpy properly. Go ahead and issue RDMA write command.

//     assert(req);
//     req->local_addr = local_addr;
//     req->remote_addr = remote_addr;

//     // We also need to send individual write cmds if not sending full page in
//     // one go.
// #ifndef FLUSH_ENTIRE_PAGE
//     assert(dirty_bitmap);

//     // Populate list of WRITE entries used to flush this page.
//     unsigned cl_writes_ptr = 0;

//     for (unsigned cl_id = 0; cl_id < NUM_CL_PER_PAGE; cl_id++) {
//         if (!is_cl_dirty(cl_id, dirty_bitmap)) {
//             continue;
//         }
//         unsigned long cl_offset = cl_id * CACHE_LINE_SIZE;
//         size_t len = CACHE_LINE_SIZE;

// #ifdef MERGE_CONTIGUOUS_LINES
//         // Consolidate consecutive dirty cachelines
//         while (((cl_id + 1) < NUM_CL_PER_PAGE) &&
//                        is_cl_dirty(cl_id + 1, dirty_bitmap)) {
//             len += CACHE_LINE_SIZE;
//             cl_id++;
//         }
//         assert((len + cl_offset) <= CHUNK_SIZE);
// #endif
//         // log_debug("Adding write cmd: cl_id=%u, cl_offset=%lu, len=%lu", cl_id,
//         // cl_offset, len);

//         // Remember this WRITE entry.
//         req->cl_writes[cl_writes_ptr].cl_offset = cl_offset;
//         req->cl_writes[cl_writes_ptr].len = len;
//         cl_writes_ptr++;
//     }

//     // Set signal that we are not using the entries beyond this CL.
//     if (cl_writes_ptr < NUM_CL_PER_PAGE) {
//         req->cl_writes[cl_writes_ptr].len = ULONG_MAX;
//     }

//     accounting(_stats.n_net_writes += cl_writes_ptr);
// #else
//     accounting(_stats.n_net_writes++);
// #endif

//     assert(server);
//     req->rkey = server->rdmakey;
//     req->size = size;
//     req->vaddr = addr;
//     req->mode = M_WRITE;
//     req->server = server;
//     req->index = req_index;
//     req->ready = 1;

// #ifndef RDMA_WRITE_IN_PFH
//     // Issue this write request
//     try_write(req_index);
// #endif

// #if defined(CACHELINE_TRACK)
//     profile_start(PERF_EVICT_CLEAN_CPY);
//     // Update the clean copy with latest page version.
//     unsigned long clean = (unsigned long)clean_buf + addr - mr->addr;
//     assert((char *)(clean + CHUNK_SIZE) < (clean_buf + CLEAN_BUF_SIZE));

//     log_debug("Updating clean version %p from %p size=%ld", (void *)clean,
//                        (void *)local_addr, size);
// #ifndef FLUSH_ENTIRE_PAGE
//     for (unsigned i = 0; i < cl_writes_ptr; i++) {
//         unsigned long cl_offset = req->cl_writes[i].cl_offset;
//         size_t len = req->cl_writes[i].len;
//         memcpy((void *)clean + cl_offset, (void *)local_addr + cl_offset, len);
//     }
// #else
//     memcpy((void *)clean, (void *)local_addr, CHUNK_SIZE);
// #endif

//     profile_stop(PERF_EVICT_CLEAN_CPY);
// #endif

//     log_debug("Done remote client write");
//     return 0;
// }

void remote_client_slab_add(struct region_t *reg, int nslabs) {
    log_debug("add new slab, contact rack cntrl %p", servers[0]);
    struct connection *conn = (struct connection *)servers[0]->rid->context;

    post_receives(conn);
    send_msg_slab_add(conn, reg, nslabs);

    // log_debug("waiting for completion of send_msg_create...");
    // wait_one_completion(reg, IBV_WC_SEND, MSG_SLAB_ADD);

    // log_debug("waiting for completion of receive response done slab add...");
    wait_one_completion(reg, IBV_WC_RECV, MSG_DONE_SLAB_ADD);

    log_info("created remote region at address addr=%lx size=%ld",
        reg->remote_addr, reg->size);
    if (reg->remote_addr == 0 && reg->size == 0) {
        log_err("Rack is out of memory!\n");
        BUG();
    }
}

void remote_client_slab_rem(struct region_t *reg) {
    struct connection *conn = (struct connection *)servers[0]->rid->context;
    post_receives(conn);
    send_msg_slab_rem(conn, reg);

    /* wait completion */
    log_debug("waiting for completion of send_msg_remove...");
    // wait_one_completion(reg, IBV_WC_SEND, MSG_SLAB_REM);
    log_debug("waiting for completion of receive response done/remove...");
    wait_one_completion(reg, IBV_WC_RECV, MSG_DONE);
}

/***************** memserver communication    *****************************/

int connect2server(int index) {
    if (index > MAX_SERVERS) {
        log_err("cannot connect to the server, index %d out of bound", index);
        BUG(); /* check server id */
    }

    struct server_conn_t *server = servers[index];
    if (server->status == CONNECTED) {
        log_info("client already connected to the server");
        return 0;
    }

    SLIST_INSERT_HEAD(&servers_list, server, link);
    remote_client_create(server, 0);
    return 0;
}

/***************** rcntrl communication    *****************************/

int connect2rcntrl(const char *ip, int port) {
    struct server_conn_t *server = servers[0];
    server->port = port;
    strcpy(server->ip, ip);

    /* ignoring fork support: ibv_fork_init(); */
    remote_client_create(server, 0);
    usleep(10);

    return 0;
}

/***************** backend supported ops *****************************/

/* backend init */
int rdma_init() {
    log_info("setting up RDMA backend for remote memory");

    /* parse remote controller info */
    char *rcntrl_ip = getenv("RDMA_RACK_CNTRL_IP" /*RCNTRL_ENV_IP*/);
    char *rcntrl_port_str = getenv("RDMA_RACK_CNTRL_PORT" /*RCNTRL_ENV_PORT*/);
    int rcntrl_port = RDMA_RACK_CNTRL_PORT;
    int i;

    if (rcntrl_ip == NULL) {
        rcntrl_ip = malloc(sizeof(RDMA_RACK_CNTRL_IP));
        assert(rcntrl_ip != NULL);
        strcpy(rcntrl_ip, RDMA_RACK_CNTRL_IP);
    }
    if (rcntrl_port_str != NULL) {
        rcntrl_port = atoi(rcntrl_port_str);
        assert(rcntrl_port > 0);
    }
    log_info("local memory=%lu, eviction_thr=%f, eviction_done_thr=%f",
        local_memory, eviction_threshold, eviction_done_threshold);        
    log_info("rcntrl_ip=%s, rcntrl_port=%d", rcntrl_ip, rcntrl_port);

    for (i = 0; i <= MAX_SERVERS; i++) {
        servers[i] = (struct server_conn_t *) malloc(sizeof(struct server_conn_t));
        assert(servers[i] != NULL);
    }

    /* connect to rcntrl and a memory server */
    SLIST_INIT(&servers_list);
    int ret = connect2rcntrl(rcntrl_ip, rcntrl_port);
    assertz(ret);

    return 0;
}

/* backend per-thread init */
int rdma_perthread_init(struct kthread *k) {
    // RDMA read/write bufs
    //   // Remember to memset the zeropage. For some reason uffd does not like
    // // zeropage to be aligned_alloc'd statically in file.
    // zero_page = aligned_alloc(CHUNK_SIZE, CHUNK_SIZE);
    // assert(zero_page);
    // memset(zero_page, 0, CHUNK_SIZE);

    // read_buf = aligned_alloc(CHUNK_SIZE, READ_BUF_SIZE);
    // assert(read_buf);

    // write_buf = aligned_alloc(CHUNK_SIZE, WRITE_BUF_SIZE);
    // assert(write_buf);

    // read_rdma_mr = ibv_reg_mr(s_ctx->pd, read_buf, READ_BUF_SIZE, IBV_ACCESS_LOCAL_WRITE);
    // assert(read_rdma_mr);

    // write_rdma_mr =
    //         ibv_reg_mr(s_ctx->pd, write_buf, WRITE_BUF_SIZE, IBV_ACCESS_LOCAL_WRITE);
    // assert(write_rdma_mr);

    // local_init();
    return 0;
}

/* backend per-thread deinit */
int rdma_perthread_destroy() {
    return 0;
}

/* backend destroy */
int rdma_destroy() {
    while (!SLIST_EMPTY(&servers_list)) {
        struct server_conn_t *s = SLIST_FIRST(&servers_list);
        /*TODO: free all server connections */
        munmap(s, sizeof(struct server_conn_t));
    }
    /*TODO: free shared RDMA data e.g., pd, cq, comp_channel, etc. */
    return 0;
}

/* add more backend memory (in slabs) and return new regions */
int rdma_add_regions(struct region_t **reg, int nslabs) {
    /* TODO: Ideally the region should be allocated after receiving completion 
     * from rdma controller that slab has been added (in on_recv_done_slab_add),
     * but just importing code from kona for now - we only support one 
     * region with single MSG_SLAB_ADD_PARTIAL response. We also don't return 
     * the regions but directly add them to regions_list */
    struct region_t *region = (struct region_t *)mmap(
        NULL, sizeof(struct region_t), PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    region->size = 0;
    remote_client_slab_add(region, nslabs);
    return 1;
}

/* add more backend memory (in slabs) and return new regions */
int rdma_free_region(struct region_t *reg) {
    /* TODO: shall we save the backend region for future allocs? */
    remote_client_slab_rem(reg);
    return 0;
}

// /* backend poll for new events */
// int poll_once() {
//     if (!ready_for_poll)
//         return 0;

//     /* send cq is async - handled by poller */
//     struct ibv_cq *cq = s_ctx->cq_send;
//     struct ibv_wc wc[NUM_POLL_CQ];

//     int ret = 0;

//     num_cqs = ibv_poll_cq(s_ctx->cq_send, NUM_POLL_CQ, wc);
//     for (unsigned int i = 0; i < num_cqs; i++) {
//         poller_on_completion(&wc[i]);
//     }

//     EXIT_KLIB();
//     return NULL;
// }

/* ops for RDMA */
struct rmem_backend_ops rdma_backend_ops = {
    .init = rdma_init,
    .perthread_init = rdma_perthread_init,
    .perthread_destroy = rdma_perthread_destroy,
    .destroy = rdma_destroy,
    .add_memory = rdma_add_regions,
    .remove_region = rdma_free_region,
};