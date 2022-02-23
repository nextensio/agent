//
//  nxt-api.h
//  NextensioApp
//
//  Created by Rudy Zulkarnain on 3/20/21.
//

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct CRegistrationInfo
{
    char *gateway;
    char *access_token;
    char *connect_id;
    char *cluster;
    char **domains;
    int num_domains;
    char *ca_cert;
    int num_cacert;
    char *userid;
    char *uuid;
    char **services;
    int num_services;
    char *hostname;
    char *model;
    char *os_type;
    char *os_name;
    int os_patch;
    int os_major;
    int os_minor;
} CRegistrationInfo;

typedef struct AgentStats
{
    int gateway_up;
    int gateway_flaps;
    int last_gateway_flap;
    int gateway_flows;
    int total_flows;
    unsigned int flows_old;
    unsigned int flows_buffered;
    unsigned int flows_dead;
    unsigned int parse_pending;
    unsigned int gateway_ip;
    unsigned int tcp_pool_cnt;
    unsigned int tcp_pool_fail_cnt;
    unsigned int tcp_pool_fail_time;
    unsigned int pkt_pool_cnt;
    unsigned int pkt_pool_fail_cnt;
    unsigned int pkt_pool_fail_time;
    unsigned int tcp_flows;
    unsigned int udp_flows;
    unsigned int dns_flows;
    unsigned int pending_rx;
    unsigned int pending_tx;
    unsigned int idle_bufs;
    unsigned int total_tunnels;
    unsigned int hogs_cleared;
} AgentStats;

void agent_init(uint32_t platform, uint32_t direct, uint32_t mtu, uint32_t highmem, uint32_t tcp_port);

int agent_started(void);

void agent_on(int32_t fd);

void agent_off(void);

void onboard(struct CRegistrationInfo info);

void agent_stats(struct AgentStats *stats);

int agent_progress(void);