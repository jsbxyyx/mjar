// mjar.cpp
#include "mjar.h"
#include <cstring>
#include <cstdlib>

#include "com_github_jsbxyyx_mjar_Mjarencrypt.h"

// void encrypt(char *data) {
//     unsigned int m = strlen(data);
//     for (int i = 0; i < m; i++) {
//         data[i] = data[i] + 8;
//     }
// }

#include "aes.hpp"
#include "pkcs7_padding.hpp"

#define CBC 1
#define CTR 1
#define ECB 1
#define AES256 1

//AES_KEY
static unsigned char AES_KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
//AES_IV
static unsigned char AES_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

jbyteArray encrypt(JNIEnv *jni_env, jbyteArray jarray) {
    jbyte *input = jni_env->GetByteArrayElements(jarray, 0);
    jsize dlen = jni_env->GetArrayLength(jarray);

    printf("padding before = %d\n", dlen);
    // padding
    int dlenu = dlen;
    if (dlen % 16 != 0) {
        dlenu += 16 - (dlen % 16);
    }
    printf("padding after = %d\n", dlenu);
    uint8_t *hexarray = (uint8_t *) malloc(dlenu);
    if (!hexarray) {
        free(input);
        return NULL;
    }
    memset(hexarray, 0, dlenu);
    for (int i = 0; i < dlen; i++) {
        hexarray[i] = (uint8_t) input[i];
    }
    printf("----- array start -----\n");
    for (int i = 0; i < dlen; ++i) {
        printf("%02x", hexarray[i]);
    }
    printf("\n----- array end -----\n");

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, AES_IV);
    AES_CBC_encrypt_buffer(&ctx, (uint8_t *) hexarray, dlenu);

    printf("----- encrypted start -----\n");
    for (int i = 0; i < dlenu; ++i) {
        printf("%02x", hexarray[i]);
    }
    printf("\n----- encrypted end -----\n");

    jbyteArray new_array = jni_env->NewByteArray(dlenu);
    jni_env->SetByteArrayRegion(new_array, 0, dlenu, (jbyte *) hexarray);

    jni_env->ReleaseByteArrayElements(jarray, input, 0);
    free(input);
    free(hexarray);

    return new_array;
}

// void decrypt(char *data) {
//     unsigned int m = strlen(data);
//     for (int i = 0; i < m; i++) {
//         data[i] = data[i] - 8;
//     }
// }

void decrypt(JNIEnv *jni_env, char *input) {
    int dlenu = strlen(input);
    uint8_t *hexarray = (uint8_t *) malloc(dlenu);
    if (!hexarray) {
        free(input);
        return;
    }
    memset(hexarray, 0, dlenu);
    for (int i = 0; i < dlenu; i++) {
        hexarray[i] = (uint8_t) input[i];
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, AES_IV);

    AES_CBC_decrypt_buffer(&ctx, hexarray, (size_t) dlenu);

    size_t actualDataLength = pkcs7_padding_data_length(hexarray, dlenu, 16);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_github_jsbxyyx_mjar_Mjarencrypt_encrypt
(JNIEnv *jni_env, jobject arg, jbyteArray _buf) {
    // char *dst = (char *) jni_env->GetByteArrayElements(_buf, 0);
    // encrypt(dst);
    // jni_env->SetByteArrayRegion(_buf, 0, strlen(dst), (jbyte *) dst);
    // return _buf;
    jbyteArray output_ = encrypt(jni_env, _buf);
    return output_;
}

// JVM 通过回调该方法启动 Agent
jvmtiEnv *m_pJvmTI = NULL;

const char *pkg = NULL;

void JNICALL CallbackClassFileLoadHook(jvmtiEnv *jvmti_env,
                                       JNIEnv *jni_env,
                                       jclass class_being_redefined,
                                       jobject loader,
                                       const char *name,
                                       jobject protection_domain,
                                       jint class_data_len,
                                       const unsigned char *class_data,
                                       jint *new_class_data_len,
                                       unsigned char **new_class_data) {
    //    printf("--- class name %s\n", name);

    if (name && strstr(name, pkg) != NULL && strstr(name, "CGLIB$$") == NULL) {
        printf("--- decrypt class %s\n", name);
        fflush(stdout);

        // *new_class_data_len = class_data_len;
        // jvmti_env->Allocate(class_data_len, new_class_data);
        // unsigned char *my_data = *new_class_data;
        //
        // for (int i = 0; i < class_data_len; i++) {
        //     my_data[i] = class_data[i];
        // }
        // decrypt((char *) my_data);

        decrypt(jni_env, (char *) class_data);
    } else {
        *new_class_data_len = class_data_len;
        jvmti_env->Allocate(class_data_len, new_class_data);
        unsigned char *my_data = *new_class_data;

        for (int i = 0; i < class_data_len; i++) {
            my_data[i] = class_data[i];
        }
    }
}

JNIEXPORT jint JNICALL
Agent_OnLoad(JavaVM *vm,
             char *options,
             void *reserved) {
    jvmtiEnv *jvmti;
    jvmtiError error;
    // Create the JVM TI environment (jvmti).
    jint result = vm->GetEnv((void **) &jvmti, JVMTI_VERSION_1_1);
    if (result != JNI_OK) {
        printf("ERROR: Unable to access JVMTI!\n");
        return 1;
    }

    pkg = options;
    printf("--- options %s\n", options);
    fflush(stdout);

    m_pJvmTI = jvmti;

    jvmtiCapabilities capabilities;
    // Clear the capabilities structure and set the ones you need.
    (void) memset(&capabilities, 0, sizeof(capabilities));
    capabilities.can_generate_all_class_hook_events = 1;
    capabilities.can_tag_objects = 1;
    capabilities.can_generate_object_free_events = 1;
    capabilities.can_get_source_file_name = 1;
    capabilities.can_get_line_numbers = 1;
    capabilities.can_generate_vm_object_alloc_events = 1;

    // Request these capabilities for this JVM TI environment.
    error = jvmti->AddCapabilities(&capabilities);
    if (error != JVMTI_ERROR_NONE) {
        printf("ERROR: Unable to AddCapabilities JVMTI!\n");
        return error;
    }

    jvmtiEventCallbacks callbacks;
    // Clear the callbacks structure and set the ones you want.
    (void) memset(&callbacks, 0, sizeof(callbacks));
    callbacks.ClassFileLoadHook = &CallbackClassFileLoadHook;

    error = jvmti->SetEventCallbacks(&callbacks, (jint) sizeof(callbacks));
    if (error != JVMTI_ERROR_NONE) {
        printf("ERROR: Unable to SetEventCallbacks JVMTI!\n");
        return error;
    }

    // For each of the above callbacks, enable this event.
    error = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                                            JVMTI_EVENT_CLASS_FILE_LOAD_HOOK,
                                            (jthread) NULL);
    if (error != JVMTI_ERROR_NONE) {
        printf("ERROR: Unable to SetEventNotificationMode JVMTI!\n");
        return error;
    }
    return JNI_OK; // Indicates to the VM that the agent loaded OK.
}
