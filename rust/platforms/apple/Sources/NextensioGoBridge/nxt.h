#ifndef NEXTENSIO_H
#define NEXTENSIO_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

struct CRegistrationInfo {
    char *host;
    char *access_token;
    char *connect_id;
    char *domains;
    int num_domains;
    char *ca_cert;
    char *userid;
    char *uuid;
    char *services;
    int num_services;
};

extern void agent_init(int platform, int direct);
extern void agent_on(int tun_fd);
extern void agent_off();
extern void onboard(struct CRegistrationInfo reginfo);

#endif
