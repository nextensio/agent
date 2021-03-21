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
  const char *host;
  const char *access_token;
  const char *connect_id;
  const char *const *domains;
  int num_domains;
  const char *ca_cert;
  const char *userid;
  const char *uuid;
  const char *const *services;
  int num_services;
} CRegistrationInfo;

void agent_init(uintptr_t platform, uintptr_t direct);

void agent_on(int32_t fd);

void agent_off(void);

void onboard(struct CRegistrationInfo info);
