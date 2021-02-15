#ifndef NEXTENSIO_H
#define NEXTENSIO_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef void(*logger_cb_t)(void *context, int level, const char *msg);
extern void nxtLogger(void *context, logger_cb_t logger_fn);
extern int nxtOn(int32_t tun_fd);
extern int nxtOff(int32_t tun_fd);
extern void nxtInit(int direct);

#endif
