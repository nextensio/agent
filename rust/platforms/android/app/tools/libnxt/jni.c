#include <jni.h>
#include <stdlib.h>

struct CRegistrationInfo
{
    const char *host;
    const char *access_token;
    const char *connect_id;
    const char *cluster;
    const char *podname;
    const char **domains;
    int num_domains;
    signed char *ca_cert;
    int num_cacert;
    const char *userid;
    const char *uuid;
    const char **services;
    int num_services;
};

struct AgentStats
{
    int gateway_up;
    int gateway_flaps;
    int last_gateway_flap;
    int gateway_flows;
    int total_flows;
};

extern void agent_init(int platform, int direct, int rxmtu, int txmtu, int highmem);
extern void agent_on(int tun_fd);
extern void agent_off();
extern void onboard(struct CRegistrationInfo reginfo);
extern void agent_stats(struct AgentStats *stats);

// We set the rxmtu size to 64*1024, with txmtu on the tun interface being 32*1024,
// and with 24 max buffers queued up at any time. Android does not perform well when
// we send too many packets close to the interface mtu size
#define RXMTU 1500
#define TXMTU 1500

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtApp_nxtInit(JNIEnv *env, jclass c, jint direct)
{
    agent_init(0 /*android*/, 1 /*direct*/, RXMTU, TXMTU, 0 /* low memory device */);
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
                                                                jstring cluster, jstring podname,
                                                                jbyteArray cacert, jobjectArray domains, jobjectArray services)
{
    struct CRegistrationInfo creg = {};

    creg.host = (*env)->GetStringUTFChars(env, host, NULL);
    creg.access_token = (*env)->GetStringUTFChars(env, accessToken, NULL);
    creg.connect_id = (*env)->GetStringUTFChars(env, connectid, NULL);
    creg.cluster = (*env)->GetStringUTFChars(env, cluster, NULL);
    creg.podname = (*env)->GetStringUTFChars(env, podname, NULL);
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
    (*env)->ReleaseStringUTFChars(env, cluster, creg.cluster);
    (*env)->ReleaseStringUTFChars(env, podname, creg.podname);
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

JNIEXPORT void JNICALL Java_nextensio_agent_NxtStats_nxtStats(JNIEnv *env, jobject obj)
{
    struct AgentStats stats = {};
    agent_stats(&stats);

    jclass thisObj = (*env)->GetObjectClass(env, obj);
    jfieldID gateway_up = (*env)->GetFieldID(env, thisObj, "gateway_up", "I");
    (*env)->SetIntField(env, obj, gateway_up, stats.gateway_up);
    jfieldID gateway_flaps = (*env)->GetFieldID(env, thisObj, "gateway_flaps", "I");
    (*env)->SetIntField(env, obj, gateway_flaps, stats.gateway_flaps);
    jfieldID last_gateway_flap = (*env)->GetFieldID(env, thisObj, "last_gateway_flap", "I");
    (*env)->SetIntField(env, obj, last_gateway_flap, stats.last_gateway_flap);
    jfieldID gateway_flows = (*env)->GetFieldID(env, thisObj, "gateway_flows", "I");
    (*env)->SetIntField(env, obj, gateway_flows, stats.gateway_flows);
    jfieldID total_flows = (*env)->GetFieldID(env, thisObj, "total_flows", "I");
    (*env)->SetIntField(env, obj, total_flows, stats.total_flows);
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
