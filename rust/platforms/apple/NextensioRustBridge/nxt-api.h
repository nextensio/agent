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
} CRegistrationInfo;

void agent_init(uintptr_t platform, uintptr_t direct, int rxmtu, int txmtu, int highmem);

int agent_started(void);

void agent_on(int32_t fd);

void agent_off(void);

void onboard(struct CRegistrationInfo info);
