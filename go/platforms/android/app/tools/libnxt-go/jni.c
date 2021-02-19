#include <jni.h>
#include <stdlib.h>

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
      int         numflows;
      int         directflows;  
};

extern void nxtInit();
extern void nxtOn(int tun_fd);
extern void nxtOff(int tun_fd);
extern void nxtStats(struct goStats *stats);


JNIEXPORT jint JNICALL Java_nextensio_agent_NxtAgent_nxtInit(JNIEnv *env, jclass c, jint direct)
{
    nxtInit(direct);
    return 0;
}

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtAgentService_nxtOn(JNIEnv *env, jclass c, jint tun_fd)
{
    nxtOn(tun_fd);
    return 0;
}

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtAgentService_nxtOff(JNIEnv *env, jclass c, jint tun_fd)
{
    nxtOff(tun_fd);
    return 0;
}

JNIEXPORT void JNICALL Java_nextensio_agent_NxtStats_nxtStats (JNIEnv *env, jobject obj)
{
    struct goStats stats = {};
    nxtStats(&stats);

    jclass thisObj = (*env)->GetObjectClass(env, obj);
    jfieldID heap = (*env)->GetFieldID(env, thisObj, "heap", "J");
    (*env)->SetLongField(env, obj, heap, stats.heap);
    jfieldID mallocs = (*env)->GetFieldID(env, thisObj, "mallocs", "J");
    (*env)->SetLongField(env, obj, mallocs, stats.mallocs);
    jfieldID frees = (*env)->GetFieldID(env, thisObj, "frees", "J");
    (*env)->SetLongField(env, obj, frees, stats.frees);
    jfieldID paused = (*env)->GetFieldID(env, thisObj, "paused", "J");
    (*env)->SetLongField(env, obj, paused, stats.paused);
    jfieldID gc = (*env)->GetFieldID(env, thisObj, "gc", "I");
    (*env)->SetIntField(env, obj, gc, stats.gc);
    jfieldID goroutines = (*env)->GetFieldID(env, thisObj, "goroutines", "I");
    (*env)->SetIntField(env, obj, goroutines, stats.goroutines);
    jfieldID conn = (*env)->GetFieldID(env, thisObj, "conn", "I");
    (*env)->SetIntField(env, obj, conn, stats.conn);
    jfieldID disco = (*env)->GetFieldID(env, thisObj, "disco", "I");
    (*env)->SetIntField(env, obj, disco, stats.disco);
    jfieldID discoSecs = (*env)->GetFieldID(env, thisObj, "discoSecs", "I");
    (*env)->SetIntField(env, obj, discoSecs, stats.discoSecs);
    jfieldID numflows = (*env)->GetFieldID(env, thisObj, "numflows", "I");
    (*env)->SetIntField(env, obj, discoSecs, stats.numflows);
    jfieldID directflows = (*env)->GetFieldID(env, thisObj, "directflows", "I");
    (*env)->SetIntField(env, obj, discoSecs, stats.directflows);
}
