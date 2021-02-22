#ifndef NEXTENSIO_H
#define NEXTENSIO_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

// NOTE: This struture has to be in sync with the commented out structure
// of the same name in apis.go. Those comments are used by cgo to generate
// a go structure from a C structure, so any change here should reflect in
// apis.go in those comments too
struct goStats {
      long long    heap;
      long long    mallocs;
      long long    frees;
      long long    paused;
      int         gc;
      int         goroutines;
      int         conn;
      int         disco;
      int         discoSecs;
};

typedef void(*logger_cb_t)(void *context, int level, const char *msg);
extern void nxtLogger(void *context, logger_cb_t logger_fn);
extern void nxtInit(int direct);
extern void nxtOn(int tun_fd);
extern void nxtOff(int tun_fd);
extern void nxtStats(struct goStats *stats);

#endif
