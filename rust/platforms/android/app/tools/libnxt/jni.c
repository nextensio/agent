#include <jni.h>
#include <stdlib.h>

struct CRegistrationInfo
{
    const char *host;
    const char *access_token;
    const char *connect_id;
    const char **domains;
    int num_domains;
    signed char *ca_cert;
    int num_cacert;
    const char *userid;
    const char *uuid;
    const char **services;
    int num_services;
};

extern void agent_init(int platform, int direct);
extern void agent_on(int tun_fd);
extern void agent_off();
extern void onboard(struct CRegistrationInfo reginfo);

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtApp_nxtInit(JNIEnv *env, jclass c, jint direct)
{
    agent_init(0 /*android*/, 1 /*direct*/);
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

JNIEXPORT void JNICALL Java_nextensio_agent_NxtAgent_nxtOnboard(JNIEnv *env, jclass c, jstring accessToken,
                                                                jstring uuid, jstring userid, jstring host, jstring connectid,
                                                                jbyteArray cacert, jobjectArray domains, jobjectArray services)
{
    struct CRegistrationInfo creg = {};

    creg.host = (*env)->GetStringUTFChars(env, host, NULL);
    creg.access_token = (*env)->GetStringUTFChars(env, accessToken, NULL);
    creg.connect_id = (*env)->GetStringUTFChars(env, connectid, NULL);
    creg.userid = (*env)->GetStringUTFChars(env, userid, NULL);
    creg.uuid = (*env)->GetStringUTFChars(env, uuid, NULL);

    creg.ca_cert = (*env)->GetByteArrayElements(env, cacert, NULL);
    creg.num_cacert = (*env)->GetArrayLength(env, cacert);

    creg.num_domains = (*env)->GetArrayLength(env, domains);
    creg.domains = malloc(creg.num_domains * sizeof(creg.domains));
    for (int i = 0; i < creg.num_domains; i++)
    {
        jstring string = (jstring)((*env)->GetObjectArrayElement(env, domains, i));
        creg.domains[i] = (*env)->GetStringUTFChars(env, string, 0);
    }

    creg.num_services = (*env)->GetArrayLength(env, services);
    creg.services = malloc(creg.num_services * sizeof(creg.services));
    for (int i = 0; i < creg.num_services; i++)
    {
        jstring string = (jstring)((*env)->GetObjectArrayElement(env, services, i));
        creg.services[i] = (*env)->GetStringUTFChars(env, string, 0);
    }

    // Call Rust to onboard
    onboard(creg);

    // done with the call to rust, release all memory
    (*env)->ReleaseStringUTFChars(env, host, creg.host);
    (*env)->ReleaseStringUTFChars(env, accessToken, creg.access_token);
    (*env)->ReleaseStringUTFChars(env, connectid, creg.connect_id);
    (*env)->ReleaseStringUTFChars(env, userid, creg.userid);
    (*env)->ReleaseStringUTFChars(env, uuid, creg.uuid);

    (*env)->ReleaseByteArrayElements(env, cacert, creg.ca_cert, 0);

    for (int i = 0; i < creg.num_domains; i++)
    {
        jstring string = (jstring)((*env)->GetObjectArrayElement(env, domains, i));
        (*env)->ReleaseStringUTFChars(env, string, creg.domains[i]);
    }
    free(creg.domains);

    for (int i = 0; i < creg.num_services; i++)
    {
        jstring string = (jstring)((*env)->GetObjectArrayElement(env, services, i));
        (*env)->ReleaseStringUTFChars(env, string, creg.services[i]);
    }
    free(creg.services);
}

// These are some symbols that rust is looking for (coming from their math/logarithm lib!), just putting
// stub APIs here. Not to confuse, these are NOT related to logging, these are stubs for some 'logarithm'
double log(double a)
{
    return 0;
}

float logf(float a)
{
    return 0;
}
