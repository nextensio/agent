#include <jni.h>
#include <stdlib.h>

struct CRegistrationInfo
{
    const char *gateway;
    const char *access_token;
    const char *connect_id;
    const char *cluster;
    const char **domains;
    int *needdns;
    const char **dnsip;
    int num_domains;
    signed char *ca_cert;
    int num_cacert;
    const char *userid;
    const char *uuid;
    const char **services;
    int num_services;
    const char *hostname;
    const char *model;
    const char *os_type;
    const char *os_name;
    int os_patch;
    int os_major;
    int os_minor;
    const char *trace_users;
};

struct AgentStats
{
    int gateway_up;
    int gateway_flaps;
    int last_gateway_flap;
    int gateway_flows;
    int total_flows;
};

extern void agent_init(uint32_t platform, uint32_t direct, uint32_t mtu, uint32_t highmem, uint32_t tcp_port);
extern void agent_on(int tun_fd);
extern void agent_off();
extern void onboard(struct CRegistrationInfo reginfo);
extern void agent_stats(struct AgentStats *stats);

#define MTU 1500

JNIEXPORT jint JNICALL Java_nextensio_agent_NxtApp_nxtInit(JNIEnv *env, jclass c, jint direct)
{
    agent_init(0 /*android*/, 0 /*direct*/, MTU, 0 /* low memory device */, 0 /* no tcp port */);
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

JNIEXPORT void JNICALL Java_nextensio_agent_NxtApp_nxtOnboard(JNIEnv *env, jclass c, jstring accessToken,
                                                              jstring uuid, jstring userid, jstring gateway, jstring connectid,
                                                              jstring cluster,
                                                              jbyteArray cacert, jobjectArray domains, jobjectArray dnsip,
                                                              jintArray needdns, jobjectArray services,
                                                              jstring hostname, jstring model, jstring ostype, jstring osname,
                                                              jint major, jint minor, jint patch,
                                                              jstring trace_users)
{
    struct CRegistrationInfo creg = {};

    creg.gateway = (*env)->GetStringUTFChars(env, gateway, NULL);
    creg.access_token = (*env)->GetStringUTFChars(env, accessToken, NULL);
    creg.connect_id = (*env)->GetStringUTFChars(env, connectid, NULL);
    creg.cluster = (*env)->GetStringUTFChars(env, cluster, NULL);
    creg.userid = (*env)->GetStringUTFChars(env, userid, NULL);
    creg.uuid = (*env)->GetStringUTFChars(env, uuid, NULL);

    creg.ca_cert = (*env)->GetByteArrayElements(env, cacert, NULL);
    creg.num_cacert = (*env)->GetArrayLength(env, cacert);

    creg.num_domains = (*env)->GetArrayLength(env, domains);
    creg.domains = malloc(creg.num_domains * sizeof(char *));
    creg.dnsip = malloc(creg.num_domains * sizeof(char *));
    creg.needdns = malloc(creg.num_domains * sizeof(int));
    jint *int_arr = (*env)->GetIntArrayElements(env, needdns, 0);
    for (int i = 0; i < creg.num_domains; i++)
    {
        jstring s1 = (jstring)((*env)->GetObjectArrayElement(env, domains, i));
        creg.domains[i] = (*env)->GetStringUTFChars(env, s1, 0);
        jstring s2 = (jstring)((*env)->GetObjectArrayElement(env, dnsip, i));
        creg.dnsip[i] = (*env)->GetStringUTFChars(env, s2, 0);
        creg.needdns[i] = int_arr[i];
    }

    creg.num_services = (*env)->GetArrayLength(env, services);
    creg.services = malloc(creg.num_services * sizeof(char *));
    for (int i = 0; i < creg.num_services; i++)
    {
        jstring s1 = (jstring)((*env)->GetObjectArrayElement(env, services, i));
        creg.services[i] = (*env)->GetStringUTFChars(env, s1, 0);
    }

    creg.hostname = (*env)->GetStringUTFChars(env, hostname, NULL);
    creg.model = (*env)->GetStringUTFChars(env, model, NULL);
    creg.os_type = (*env)->GetStringUTFChars(env, ostype, NULL);
    creg.os_name = (*env)->GetStringUTFChars(env, osname, NULL);
    creg.os_major = major;
    creg.os_minor = minor;
    creg.os_patch = patch;

    creg.trace_users = (*env)->GetStringUTFChars(env, trace_users, NULL);

    // Call Rust to onboard
    onboard(creg);

    // done with the call to rust, release all memory
    (*env)->ReleaseStringUTFChars(env, gateway, creg.gateway);
    (*env)->ReleaseStringUTFChars(env, accessToken, creg.access_token);
    (*env)->ReleaseStringUTFChars(env, connectid, creg.connect_id);
    (*env)->ReleaseStringUTFChars(env, cluster, creg.cluster);
    (*env)->ReleaseStringUTFChars(env, userid, creg.userid);
    (*env)->ReleaseStringUTFChars(env, uuid, creg.uuid);

    (*env)->ReleaseByteArrayElements(env, cacert, creg.ca_cert, 0);

    for (int i = 0; i < creg.num_domains; i++)
    {
        jstring s1 = (jstring)((*env)->GetObjectArrayElement(env, domains, i));
        (*env)->ReleaseStringUTFChars(env, s1, creg.domains[i]);
        jstring s2 = (jstring)((*env)->GetObjectArrayElement(env, dnsip, i));
        (*env)->ReleaseStringUTFChars(env, s2, creg.dnsip[i]);
    }
    free(creg.domains);
    free(creg.dnsip);
    free((void *)creg.needdns);
    (*env)->ReleaseIntArrayElements(env, needdns, int_arr, 0);

    for (int i = 0; i < creg.num_services; i++)
    {
        jstring s1 = (jstring)((*env)->GetObjectArrayElement(env, services, i));
        (*env)->ReleaseStringUTFChars(env, s1, creg.services[i]);
    }
    free(creg.services);

    (*env)->ReleaseStringUTFChars(env, hostname, creg.hostname);
    (*env)->ReleaseStringUTFChars(env, model, creg.model);
    (*env)->ReleaseStringUTFChars(env, ostype, creg.os_type);
    (*env)->ReleaseStringUTFChars(env, osname, creg.os_name);
    (*env)->ReleaseStringUTFChars(env, trace_users, creg.trace_users);
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
