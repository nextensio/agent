#include <jni.h>
#include <stdlib.h>

extern int nxtOn(int tun_fd);

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtAgentService_nxtOn(JNIEnv *env, jclass c, jint tun_fd)
{
    int ret = nxtOn(tun_fd);
    return ret;
}
