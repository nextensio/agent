#ifndef NEXTENSIO_H
#define NEXTENSIO_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

extern void agent_init(int platform, int direct);
extern void agent_on(int tun_fd);
extern void agent_off();

#endif
