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
    int *needdns;
    char **dnsip;
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

void agent_init(uint32_t platform, uint32_t direct, uint32_t rxmtu, uint32_t txmtu, uint32_t highmem, uint32_t tcp_port);

int agent_started(void);

void agent_on(int32_t fd);
void agent_default_route(uint32_t bindip);

void agent_off(void);

void onboard(struct CRegistrationInfo info);
