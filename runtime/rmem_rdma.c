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
#include "rmem/fault.h"
#include "rmem/rdma.h"
#include "defs.h"

/** 
 * Per-connection QP and CQ sizes for send and recv. We only expect a lot of 
 * outward (send) communication and that too on datapath QPs. CQs are shared 
 * for each channel
 */
#define CQ_RECV_SIZE            10
#define CQ_SEND_SIZE            MAX_REQS_PER_CHAN
#define DATAPATH_CQ_SIZE        MAX_REQS_PER_CHAN

/* memory buf size */
#define BUF_ENTRY_SIZE      (CHUNK_SIZE * RMEM_MAX_CHUNKS_PER_OP)
#define READ_BUF_SIZE       (BUF_ENTRY_SIZE * MAX_R_REQS_PER_CONN_CHAN)
#define WRITE_BUF_SIZE      (BUF_ENTRY_SIZE * MAX_W_REQS_PER_CONN_CHAN)
BUILD_ASSERT(READ_BUF_SIZE >= CHUNK_SIZE);
BUILD_ASSERT(WRITE_BUF_SIZE >= CHUNK_SIZE);

/* global state */
struct server_conn_t* servers[MAX_SERVERS + 1];
SLIST_HEAD(servers_listhead, server_conn_t);
struct servers_listhead servers_list;
static struct context *global_ctx = NULL;

/* thread-local state */
__thread struct ibv_wc wc[RMEM_MAX_COMP_PER_OP];

/* forward declarations */
static int on_route_resolved(struct rdma_cm_id *id);
static int on_completion(struct ibv_wc *wc, struct region_t *reg,
    enum ibv_wc_opcode opcode, int msgtype);
static int connect2server(int index);

/*************** RDMA connection setup help *********************************/

/** 
 * Listen on RCNTRL recv cq for slab add/remove and other events (sync) 
 */
static void wait_rcntrl_response(struct connection* rcntrl, 
    struct region_t *reg, enum ibv_wc_opcode opcode, int msgtype) 
{
    struct ibv_cq *cq;
    struct ibv_wc wc;
    int ret = 0;

    log_debug("wait one response from rcntrl");
    assert(msgtype < NUM_MSG_TYPE);
    cq = rcntrl->cq_recv;
    while (1) {
        if (ibv_poll_cq(cq, 1, &wc)) {
            ret = on_completion(&wc, reg, opcode, msgtype);
            if (msgtype != MSG_DONE_SLAB_ADD 
                || (msgtype == MSG_DONE_SLAB_ADD && ret))
                break;
        }
    }
}

/**
 * Region add on slab add ack from the controller
 */
void on_recv_done_slab_add(struct connection *conn, struct region_t *reg)
{
    struct message* msg;
    struct server_conn_t *server;
    int r;

    /* add server to our list. currently, the server and region are one-to-one
     * coupled - so we should only be adding the server once in lifetime */
    msg = conn->recv_msg;
    server = servers[msg->data.id];
    BUG_ON(server->status == CONNECTED);    /* adding server twice! */
    strcpy(server->ip, msg->data.ip);
    server->port = msg->data.port;
    server->id = msg->data.id;
    server->rdmakey = msg->data.rdmakey;
    server->size = ((unsigned long)msg->data.nslabs) * RDMA_SERVER_SLAB_SIZE;
    server->status = (server->status == CONNECTED ? CONNECTED : DISCONNECTED);
    assert(server->size % PAGE_SIZE == 0); 
    log_info("granted slabs:%d, server size: %ld", msg->data.nslabs, server->size);

    /* init & register region */
    reg->remote_addr = (unsigned long)msg->data.addr;
    reg->server = server;
    reg->size = server->size;
    r = register_memory_region(reg, 1);
    assertz(r);
    assert(reg->addr);
    log_debug("%s:slab added on server:%s, port:%d, id:%d, at address %p",
        __func__, server->ip, server->port, server->id, (void *)reg->remote_addr);

    if (server->status == DISCONNECTED) {
        r = connect2server(server->id);
        assertz(r);
    }
}

void on_recv_done(struct connection *conn, struct region_t *reg) {
    log_debug("received done! %p", conn->recv_msg->data.addr);
}

/**
 * Completion for control path messages
 */
static int on_completion(struct ibv_wc *wc, struct region_t *reg, 
        enum ibv_wc_opcode opcode, int msgtype) 
{
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

/**
 * Create and register all the memory bufs needed for a connection
 */
void create_register_memory_buf(struct connection *conn) 
{
    size_t size;

    /* send/revc bufs */
    conn->send_msg = malloc(sizeof(struct message));
    assert(conn->send_msg);

    conn->recv_msg = malloc(sizeof(struct message));
    assert(conn->recv_msg);

    conn->send_mr = ibv_reg_mr(global_ctx->pd, conn->send_msg, 
        sizeof(struct message), IBV_ACCESS_LOCAL_WRITE);
    assert(conn->send_mr);

    conn->recv_mr = ibv_reg_mr(global_ctx->pd, conn->recv_msg, 
        sizeof(struct message), IBV_ACCESS_LOCAL_WRITE);
    assert(conn->recv_mr);

    /* read/write bufs (only required for datapath qps) */
    if (conn->datapath) {
        conn->read_buf = aligned_alloc(CHUNK_SIZE, READ_BUF_SIZE);
        assert(conn->read_buf);

        conn->write_buf = aligned_alloc(CHUNK_SIZE, WRITE_BUF_SIZE);
        assert(conn->write_buf);

        conn->read_mr = ibv_reg_mr(global_ctx->pd, conn->read_buf, 
            READ_BUF_SIZE, IBV_ACCESS_LOCAL_WRITE);
        assert(conn->read_mr);

        conn->write_mr = ibv_reg_mr(global_ctx->pd, conn->write_buf, 
            WRITE_BUF_SIZE, IBV_ACCESS_LOCAL_WRITE);
        assert(conn->write_mr);

        size = MAX_R_REQS_PER_CONN_CHAN * sizeof(request_t);
        conn->read_reqs = aligned_alloc(CACHE_LINE_SIZE, size);
        assert(conn->read_reqs);
        memset(conn->read_reqs, 0, size);
        conn->read_req_idx = 0;

        conn->write_reqs = aligned_alloc(CACHE_LINE_SIZE, 
            MAX_W_REQS_PER_CONN_CHAN * sizeof(request_t));
        assert(conn->write_reqs);
        memset(conn->write_reqs, 0, size);
        conn->write_req_idx = 0;
    }
}

/**
 * Create common global RDMA objects
 */
void build_global_context(struct ibv_context *verbs)
{
    int i;
    if (global_ctx) {
        assert(global_ctx->ctx == verbs);
        return;
    }

    /* save device */
    global_ctx = (struct context *) malloc(sizeof(struct context));
    assert(global_ctx);
    global_ctx->ctx = verbs;

    /* create pd (to be used for all qps) */
    global_ctx->pd = ibv_alloc_pd(global_ctx->ctx);
	assert(global_ctx->pd);

    /* create shared cqs */
   	global_ctx->cc = ibv_create_comp_channel(global_ctx->ctx);
	assert(global_ctx->cc);
    global_ctx->cq_send = ibv_create_cq(global_ctx->ctx, 
        CQ_SEND_SIZE, NULL, global_ctx->cc, 0);
    assert(global_ctx->cq_send);
    global_ctx->cq_recv = ibv_create_cq(global_ctx->ctx, 
        CQ_RECV_SIZE, NULL, global_ctx->cc, 0);
    assert(global_ctx->cq_recv);

    /* create datapath cqs, one per channel */
    for (i = 0; i < RMEM_MAX_CHANNELS; i++) {
        global_ctx->dp_cc[i] = ibv_create_comp_channel(global_ctx->ctx);
        assert(global_ctx->dp_cc[i]);
        global_ctx->dp_cq[i] = ibv_create_cq(global_ctx->ctx, DATAPATH_CQ_SIZE, 
            NULL, global_ctx->dp_cc[i], 0);
        assert(global_ctx->dp_cq[i]);
    }
}

/* initiate connection with a server */
void init_connection(struct connection* conn, char ip[36], int port)
{
    int ret;
    char portstr[10];
    struct addrinfo *addr = NULL;

    /* get server address */
    sprintf(portstr, "%d", port);
    log_info("client connection to server %s on port %s", ip, portstr);
    ret = getaddrinfo(ip, portstr, NULL, &addr);
    assertz(ret);

    conn->chan = rdma_create_event_channel();
    assert(conn->chan);
    ret = rdma_create_id(conn->chan, &(conn->id), NULL, RDMA_PS_TCP);
    assertz(ret);
    ret = rdma_resolve_addr(conn->id, NULL, addr->ai_addr, TIMEOUT_IN_MS);
    assertz(ret);

    /* add back ref */
    conn->id->context = conn;

    assert(addr != NULL);
    freeaddrinfo(addr);
}

/* start connection; allocate QPs and CQs */
void build_connection(struct rdma_cm_id *id)
{
    struct ibv_qp_init_attr qp_attr;
    struct connection* conn;
    int ret;

    /* get associated conn */
    assert(id->context);
    conn = (struct connection*) id->context;

    /* common resources */
    build_global_context(id->verbs);

    /* assign completion queues */
    if (conn->use_global_cq) {
        conn->cc = global_ctx->cc;
        conn->cq_send = global_ctx->cq_send;
        conn->cq_recv = global_ctx->cq_recv;
    }
    else {
        assert(conn->one_send_recv_cq);
        conn->cc = global_ctx->dp_cc[conn->dp_chan_id];
        conn->cq_send = global_ctx->dp_cq[conn->dp_chan_id];
        conn->cq_recv = global_ctx->dp_cq[conn->dp_chan_id];
    }

    /* create QP */
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.send_cq = conn->cq_send;
    qp_attr.recv_cq = conn->cq_recv;
    qp_attr.qp_type = IBV_QPT_RC;

    qp_attr.cap.max_send_wr = CQ_SEND_SIZE;
    qp_attr.cap.max_recv_wr = CQ_RECV_SIZE;
    qp_attr.cap.max_send_sge = 1;
    qp_attr.cap.max_recv_sge = 1;

    ret = rdma_create_qp(id, global_ctx->pd, &qp_attr);
    assertz(ret);
    conn->qp = id->qp;
    conn->connected = 0;

    /* create and post receive buf */
    create_register_memory_buf(conn);
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
    
    /* check that this event was associated with a conn */
    assert(event->id->context);

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

/* Follow-through on the ping-pong of RDMA connection setup */
void follow_connection_setup(struct rdma_event_channel* chan)
{
    struct rdma_cm_event *event = NULL;

    /* follow-through on connection setup */
    while (rdma_get_cm_event(chan, &event) == 0) {
        struct rdma_cm_event event_copy;
        memcpy(&event_copy, event, sizeof(*event));
        rdma_ack_cm_event(event);
        if (on_event(&event_copy)) break;
    }
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
    // wait_rcntrl_response(conn, reg, IBV_WC_SEND, MSG_SLAB_REM);
    // wait_rcntrl_response(conn, reg, IBV_WC_RECV, MSG_DONE);
}

/**
 * Setup connections with the remote server (with one control connection and  
 * specified number of dataplane connections)
 */
void remote_server_setup(struct server_conn_t *server) 
{
    int i;

    /* init connection metadata */
    assert(server != NULL);
    assert(server->num_dp <= RMEM_MAX_CHANNELS);
    server->cp.datapath = 0;
    server->cp.use_global_cq = 1;
    server->cp.server = server;
    for (i = 0; i < server->num_dp; i++) {
        server->dp[i].datapath = 1;
        server->dp[i].dp_chan_id = i;
        server->dp[i].use_global_cq = 0;
        server->dp[i].one_send_recv_cq = 1;  /* share CQ for datapath QPs */
        server->dp[i].server = server;
    }

    /* setup control path */
    init_connection(&(server->cp), server->ip, server->port);
    follow_connection_setup(server->cp.chan);

    /* we expect to be connected at this point */
    assert(server->cp.connected);
    log_info("server %s on port %d: control qp done", server->ip, server->port);
    server->status = CONNECTED;

    /* setup data path queues */
    for (i = 0; i < server->num_dp; i++) {
        init_connection(&(server->dp[i]), server->ip, server->port);
        follow_connection_setup(server->dp[i].chan);
        assert(server->dp[i].connected);
        log_info("server %s on port %d: datapath qp %d done", 
            server->ip, server->port, i);
    }
}

void remote_client_destroy(struct server_conn_t *server) {
    int i;
    log_info("remote client destroy");
    rdma_destroy_event_channel(server->cp.chan);
    for(i = 0; i < server->num_dp; i++)
        rdma_destroy_event_channel(server->dp[i].chan);
    server->status = DISCONNECTED;
}

void remote_client_slab_add(struct region_t *reg, int nslabs) {
    log_debug("add new slab, contact rack cntrl %p", servers[0]);
    struct connection *conn = (struct connection *)&(servers[0]->cp);

    post_receives(conn);
    send_msg_slab_add(conn, reg, nslabs);

    // log_debug("waiting for completion of send_msg_create...");
    // wait_rcntrl_response(conn, reg, IBV_WC_SEND, MSG_SLAB_ADD);

    // log_debug("waiting for completion of receive response done slab add...");
    wait_rcntrl_response(conn, reg, IBV_WC_RECV, MSG_DONE_SLAB_ADD);

    log_info("created remote region at address addr=%lx size=%ld",
        reg->remote_addr, reg->size);
    if (reg->remote_addr == 0 && reg->size == 0) {
        log_err("Rack is out of memory!\n");
        BUG();
    }
}

void remote_client_slab_rem(struct region_t *reg) {
    log_debug("remove slab, contact rack cntrl %p", servers[0]);
    struct connection *conn = (struct connection *)&(servers[0]->cp);
    post_receives(conn);
    send_msg_slab_rem(conn, reg);

    /* wait completion */
    log_debug("waiting for completion of send_msg_remove...");
    // wait_rcntrl_response(conn, reg, IBV_WC_SEND, MSG_SLAB_REM);
    log_debug("waiting for completion of receive response done/remove...");
    wait_rcntrl_response(conn, reg, IBV_WC_RECV, MSG_DONE);
}

/***************** memserver communication    *****************************/

int connect2server(int index) {
    if (index > MAX_SERVERS) {
        log_err("cannot connect to the server, index %d out of bound", index);
        BUG(); /* check server id */
    }

    struct server_conn_t *server = servers[index];
    if (server->status == CONNECTED) {
        log_info("client already added/connected to the server");
        return 0;
    }

    SLIST_INSERT_HEAD(&servers_list, server, link);
    server->num_dp = RMEM_MAX_CHANNELS;
    remote_server_setup(server);
    return 0;
}

/***************** rcntrl communication    *****************************/

int connect2rcntrl(const char *ip, int port) {
    struct server_conn_t *server = servers[0];
    server->port = port;
    strcpy(server->ip, ip);

    /* ignoring fork support: ibv_fork_init(); */
    server->num_dp = 0;
    remote_server_setup(server);
    usleep(10);
    return 0;
}

/***************** backend supported ops *****************************/

/* backend init */
int rdma_init() {
    int i;

    /* parse remote controller info */
    log_info("setting up RDMA backend for remote memory");
    char *rcntrl_ip = getenv("RDMA_RACK_CNTRL_IP" /*RCNTRL_ENV_IP*/);
    char *rcntrl_port_str = getenv("RDMA_RACK_CNTRL_PORT" /*RCNTRL_ENV_PORT*/);

    if (rcntrl_ip == NULL) {
        rcntrl_ip = malloc(sizeof(RDMA_RACK_CNTRL_IP));
        assert(rcntrl_ip != NULL);
        strcpy(rcntrl_ip, RDMA_RACK_CNTRL_IP);
    }
    int rcntrl_port = RDMA_RACK_CNTRL_PORT;
    if (rcntrl_port_str != NULL)
        rcntrl_port = atoi(rcntrl_port_str);
    assert(rcntrl_port > 0);
    log_info("rcntrl_ip=%s, rcntrl_port=%d", rcntrl_ip, rcntrl_port);

    /* alloc server objects */
    for (i = 0; i <= MAX_SERVERS; i++) {
        servers[i] = malloc(sizeof(struct server_conn_t));
        assert(servers[i]);
        memset(servers[i], 0, sizeof(struct server_conn_t));
    }

    /* connect to rcntrl and a memory server */
    SLIST_INIT(&servers_list);
    int ret = connect2rcntrl(rcntrl_ip, rcntrl_port);
    return ret;
}

/* backend destroy */
int rdma_destroy() {
    while (!SLIST_EMPTY(&servers_list)) {
        struct server_conn_t *s = SLIST_FIRST(&servers_list);
        remote_client_destroy(s);
        munmap(s, sizeof(struct server_conn_t));
    }
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

/* post read on a channel */
int rdma_post_read(int chan_id, fault_t* f) 
{
    struct connection *conn;
    unsigned long remote_addr, local_addr;
    size_t size;
    int req_id;
    
    /* get connection */
    assert(chan_id >= 0 && chan_id < nchans_bkend);
    conn = &(f->mr->server->dp[chan_id]);
    assert(conn->datapath);

    /* do we have a free slot? */
    req_id = conn->read_req_idx;
    assert(req_id >= 0 && req_id < MAX_R_REQS_PER_CONN_CHAN);
    if (conn->read_reqs[req_id].busy)
        /* all slots busy, try again */
        return EAGAIN;

    /* infer addrs */
    remote_addr = f->mr->remote_addr + (f->page - f->mr->addr);
    local_addr = (unsigned long)conn->read_buf + BUF_ENTRY_SIZE * req_id;
    size = CHUNK_SIZE * (1 + f->rdahead);
    assert(size <= BUF_ENTRY_SIZE);

    /* take this slot */
    log_debug("%s - read request available index=%d", FSTR(f), req_id);
    conn->read_reqs[req_id].busy = 1;
    conn->read_reqs[req_id].index = req_id;
    conn->read_reqs[req_id].local_addr = local_addr;
    conn->read_reqs[req_id].orig_local_addr = f->page;
    conn->read_reqs[req_id].remote_addr = remote_addr;
    conn->read_reqs[req_id].lkey = conn->read_mr->lkey;
    conn->read_reqs[req_id].rkey = conn->server->rdmakey;
    conn->read_reqs[req_id].size = size;
    conn->read_reqs[req_id].mode = M_READ;
    conn->read_reqs[req_id].conn = conn;

    /* post read */
    log_debug("%s - READ remote_addr %lx into local_addr %lx, size %lu", FSTR(f), 
        remote_addr, f->page, size);
    do_rdma_op(&conn->read_reqs[req_id], true);

    /* increment req_id */
    conn->read_req_idx++;
    assert(req_id + 1 == conn->read_req_idx); /*no unexpected concurrent reads*/
    if (conn->read_req_idx >= MAX_R_REQS_PER_CONN_CHAN) 
        conn->read_req_idx = 0;

    /* success */
    return 0;
}

/* post write on a channel */
int rdma_post_write(int chan_id, struct region_t* mr, unsigned long addr, 
    size_t size) 
{
    struct connection *conn;
    unsigned long remote_addr, local_addr;
    int req_id;
    
    /* get connection */
    assert(chan_id >= 0 && chan_id < nchans_bkend);
    conn = &(mr->server->dp[chan_id]);
    assert(conn->datapath);

    /* do we have a free slot? */
    req_id = conn->write_req_idx;
    assert(req_id >= 0 && req_id < MAX_W_REQS_PER_CONN_CHAN);
    if (conn->write_reqs[req_id].busy)
        /* all slots busy, try again */
        return EAGAIN;

    /* infer addrs */
    remote_addr = mr->remote_addr + (addr - mr->addr);
    local_addr = (unsigned long) conn->read_buf + BUF_ENTRY_SIZE * req_id;
    assert(size <= BUF_ENTRY_SIZE);

    /* take this slot */
    log_debug("write request available addr=%lx index=%d", addr, req_id);
    conn->write_reqs[req_id].busy = 1;
    conn->write_reqs[req_id].index = req_id;
    conn->write_reqs[req_id].local_addr = local_addr;
    conn->write_reqs[req_id].orig_local_addr = addr;
    conn->write_reqs[req_id].remote_addr = remote_addr;
    conn->write_reqs[req_id].lkey = conn->write_mr->lkey;
    conn->write_reqs[req_id].rkey = conn->server->rdmakey;
    conn->write_reqs[req_id].size = size;
    conn->write_reqs[req_id].mode = M_WRITE;
    conn->write_reqs[req_id].conn = conn;

    /* copy page into rdma-registered local buf */
    memcpy((void *)local_addr, (void *)addr, size);

    /* post write */
    log_debug("WRITE remote_addr %lx from local_addr %lx, size %lu", 
        remote_addr, local_addr, size);
    do_rdma_op(&conn->write_reqs[req_id], true);

    /* increment req_id */
    conn->write_req_idx++;
    assert(req_id + 1 == conn->write_req_idx); /*no unexpected concurrent reads*/
    if (conn->write_req_idx >= MAX_W_REQS_PER_CONN_CHAN) 
        conn->write_req_idx = 0;

    /* success */
    return 0;
}

/* backend check for read & write completions on a channel */
int rdma_check_cq(int chan_id, struct completion_cbs* cbs, int max_cqe, 
    int* nread, int* nwrite)
{
    struct request* req;
    struct ibv_cq *cq;
    int ncqe, r, i;
    enum ibv_wc_opcode opcode;
    
    /* get CQ to poll */
    assert(max_cqe > 0 && max_cqe <= RMEM_MAX_COMP_PER_OP);
    assert(chan_id >= 0 && chan_id < nchans_bkend);
    cq = global_ctx->dp_cq[chan_id];

    /* poll */
    ncqe = ibv_poll_cq(cq, max_cqe, wc);
    for (i = 0; i < ncqe; i++) {
        /* check status */
        opcode = wc->opcode;
        if (wc->status != IBV_WC_SUCCESS) {
            log_err("RDMA request failed with status %d: %s", wc->status,
                ibv_wc_status_str(wc->status));
            BUG();
        }

        /* handle return cases */
        if ((opcode & IBV_WC_RECV) || (opcode & IBV_WC_SEND)) {
            /* not expecting any send/recv traffic on datapath */
            BUG();
        } else if (opcode == IBV_WC_RDMA_READ) {
            /* handle read completion */
            req = (struct request*)(uintptr_t)wc->wr_id;
            assert(req && req->fault);
            log_debug("%s - RDMA READ completed successfully", FSTR(req->fault));
           
            /* call completion hook */
            r = cbs->read_completion(req->fault, req->local_addr, req->size);
            assertz(r);

            /* release request slot */
            req->busy = 0;
            RSTAT(NET_READ)++;
            if (nread)  (*nread)++;
        } else {
            /* handle write completion */
            assert(opcode == IBV_WC_RDMA_WRITE);
            req = (struct request*)(uintptr_t)wc->wr_id;
            assert(req && req->conn && req->conn->server); 
            assert(req->conn->server->reg);
            log_debug("RDMA WRITE completed on chan %d: index=%d, addr=%lx", 
                chan_id, req->index, req->orig_local_addr);

            /* call completion hook */
            r = cbs->write_completion(req->conn->server->reg, 
                req->orig_local_addr, req->size);
            assertz(r);

            /* release request slot */
            req->busy = 0;
            RSTAT(NET_WRITE)++;
            if (nwrite)  (*nwrite)++;
        }
    }

    assert(!(nread && nwrite) || (*nread + *nwrite == ncqe));
    return ncqe;
}

/* Ops for RDMA backend */
struct rmem_backend_ops rdma_backend_ops = {
    .init = rdma_init,
    .get_new_data_channel = backend_get_data_channel,
    .destroy = rdma_destroy,
    .add_memory = rdma_add_regions,
    .remove_region = rdma_free_region,
    .post_read = rdma_post_read,
    .post_write = rdma_post_write,
    .check_for_completions = rdma_check_cq,
};