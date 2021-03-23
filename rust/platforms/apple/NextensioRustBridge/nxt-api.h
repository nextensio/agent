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

typedef struct CRegistrationInfo {
    char *host;
    char *access_token;
    char *connect_id;
    char *domains;
    int num_domains;
    char *ca_cert;
    int num_cacert;
    char *userid;
    char *uuid;
    char *services;
    int num_services;
} CRegistrationInfo;

void agent_init(uintptr_t platform, uintptr_t direct);

void agent_on(int32_t fd);

void agent_off(void);

void onboard(struct CRegistrationInfo info);
