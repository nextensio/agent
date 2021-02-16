#include <jni.h>
#include <stdlib.h>

extern void nxtInit();
extern void nxtOn(int tun_fd);
extern void nxtOff(int tun_fd);

// Debug statistics collection APIs below. Its a TODO to somehow make this one API call 
// and return a java class with all these fields in one shotextern jlong nxtHeap();
extern jlong nxtHeap();
extern jlong nxtMallocs();
extern jlong nxtFrees();
extern jlong nxtPaused();
extern jlong nxtGoroutines();
extern jlong nxtTunDisco();
extern jlong nxtTunConn();
extern jlong nxtTunDiscoSecs();

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

// Debug statistics collection APIs below. Its a TODO to somehow make this one API call 
// and return a java class with all these fields in one shot

JNIEXPORT jlong JNICALL Java_nextensio_agent_NxtAgent_nxtHeap(JNIEnv *env, jclass c)
{
    return nxtHeap();
}

JNIEXPORT jlong JNICALL Java_nextensio_agent_NxtAgent_nxtMallocs(JNIEnv *env, jclass c)
{
    return nxtMallocs();
}

JNIEXPORT jlong JNICALL Java_nextensio_agent_NxtAgent_nxtFrees(JNIEnv *env, jclass c)
{
    return nxtFrees();
}

JNIEXPORT jlong JNICALL Java_nextensio_agent_NxtAgent_nxtPaused(JNIEnv *env, jclass c)
{
    return nxtPaused();
}

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtAgent_nxtGoroutines(JNIEnv *env, jclass c)
{
    return nxtGoroutines();
}

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtAgent_nxtTunDisco(JNIEnv *env, jclass c)
{
    return nxtTunDisco();
}

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtAgent_nxtTunConn(JNIEnv *env, jclass c)
{
    return nxtTunConn();
}

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtAgent_nxtTunDiscoSecs(JNIEnv *env, jclass c)
{
    return nxtTunDiscoSecs();
}

