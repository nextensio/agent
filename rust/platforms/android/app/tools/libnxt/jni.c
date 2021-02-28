#include <jni.h>
#include <stdlib.h>

extern void agent_init(int platform, int direct);
extern void agent_on(int tun_fd);
extern void agent_off();

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtAgent_nxtInit(JNIEnv *env, jclass c, jint direct)
{
    agent_init(0 /*android*/, 1/*direct*/);
    return 0;
}

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtAgentService_nxtOn(JNIEnv *env, jclass c, jint tun_fd)
{
    agent_on(tun_fd);
    return 0;
}

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtAgentService_nxtOff(JNIEnv *env, jclass c, jint tun_fd)
{
    agent_off();
    return 0;
}


// These are some symbols that rust is looking for (coming from their math/logarithm lib!), just putting
// stub APIs here. Not to confuse, these are NOT related to logging, these are stubs for some 'logarithm'
void log()
{
}

void logf()
{
}


