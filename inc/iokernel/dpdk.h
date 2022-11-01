/*
 * dpdk.h - shared references to DPDK
 */

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_tcp.h>
#include <rte_version.h>

/**
 * Support for both DPDK 19.11 with backwards compatibility
 */
#if RTE_VERSION >= RTE_VERSION_NUM(19,11,0,0)
/* from DPDK 19.11 */
#define IOK_ETH_MAX_LEN         ETH_MAX_LEN
#define IOK_ETH_ADDR_LEN        ETH_ADDR_LEN
#define IOK_ETH_RSS_TCP         ETH_RSS_NONFRAG_IPV4_TCP
#define IOK_ETH_RSS_UDP         ETH_RSS_NONFRAG_IPV4_UDP
typedef struct rte_ether_addr   iok_rte_eth_addr_t;
typedef struct rte_ether_hdr    iok_rte_eth_hdr_t;
typedef struct rte_tcp_hdr      iok_rte_tcp_hdr_t;
typedef struct rte_ipv4_hdr     iok_rte_ipv4_hdr_t;
#define IS_UNICAST_ETH_ADDR     rte_is_unicast_ether_addr
#define IS_BRDCST_ETH_ADDR      rte_is_broadcast_ether_addr

#else
/* from DPDK 18.11 */
#define IOK_ETH_MAX_LEN         ETHER_MAX_LEN
#define IOK_ETH_ADDR_LEN        ETHER_ADDR_LEN
#define IOK_ETH_RSS_TCP         ETH_RSS_TCP
#define IOK_ETH_RSS_UDP         ETH_RSS_UDP
typedef struct ether_addr       iok_rte_eth_addr_t;
typedef struct ether_hdr        iok_rte_eth_hdr_t;
typedef struct tcp_hdr          iok_rte_tcp_hdr_t;
typedef struct ipv4_hdr         iok_rte_ipv4_hdr_t;
#define IS_UNICAST_ETH_ADDR     is_unicast_ether_addr
#define IS_BRDCST_ETH_ADDR      is_broadcast_ether_addr

#endif
