#include <jni.h>
#include <stdlib.h>

extern int nxtInit();
extern int nxtOn(int tun_fd);

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
