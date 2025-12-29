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

#define LOG_DEBUG getenv("MJAR_LOG_DEBUG") != NULL

//AES_KEY
static unsigned char AES_KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
//AES_IV
static unsigned char AES_IV[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static jbyteArray encrypt(JNIEnv *jni_env, jbyteArray jarray) {
    jbyte *input = jni_env->GetByteArrayElements(jarray, 0);
    jsize data_length = jni_env->GetArrayLength(jarray);

    if (LOG_DEBUG) {
        printf("padding before = %d\n", data_length);
    }
    // padding
    uint8_t padding_length = pkcs7_padding_pad_count(data_length, AES_BLOCKLEN);
    if (LOG_DEBUG) {
        printf("padding val : %02x\n", padding_length);
    }
    int data_padded_length = data_length + padding_length;
    uint8_t *hexarray = (uint8_t *) malloc(data_padded_length);
    if (hexarray == NULL) {
        jni_env->ReleaseByteArrayElements(jarray, input, 0);
        return NULL;
    }
    memset(hexarray, 0, data_padded_length);
    memcpy(hexarray, input, data_length);
    if (LOG_DEBUG) {
        printf("----- log array start -----\n");
        for (int i = 0; i < data_length; ++i) {
            printf("%02x", hexarray[i]);
        }
        printf("\n----- log array end -----\n");
    }

    pkcs7_padding_add_padding(hexarray, data_padded_length, data_length);
    if (LOG_DEBUG) {
        printf("----- log padding start -----\n");
        for (int i = data_length; i < data_padded_length; ++i) {
            printf("%02x", hexarray[i]);
        }
        printf("\n----- log padding end -----\n");
        printf("padding after = %d\n", data_padded_length);
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, AES_IV);
    AES_CBC_encrypt_buffer(&ctx, (uint8_t *) hexarray, data_padded_length);
    if (LOG_DEBUG) {
        printf("----- log encrypted start -----\n");
        for (int i = 0; i < data_padded_length; ++i) {
            printf("%02x", hexarray[i]);
        }
        printf("\n----- log encrypted end -----\n");
    }

    jbyteArray new_array = jni_env->NewByteArray(data_padded_length);
    jni_env->SetByteArrayRegion(new_array, 0, data_padded_length, (jbyte *) hexarray);

    jni_env->ReleaseByteArrayElements(jarray, input, 0);
    free(hexarray);

    return new_array;
}

// void decrypt(char *data) {
//     unsigned int m = strlen(data);
//     for (int i = 0; i < m; i++) {
//         data[i] = data[i] - 8;
//     }
// }

static jbyteArray decrypt(JNIEnv *jni_env, const char *name, unsigned char *data, size_t data_length) {
    uint8_t *hexarray = (uint8_t *) malloc(data_length);
    if (hexarray == NULL) {
        return NULL;
    }
    memset(hexarray, 0, data_length);
    memcpy(hexarray, data, data_length);

    if (LOG_DEBUG) {
        printf("remove padding before = %d\n", data_length);
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, AES_IV);
    AES_CBC_decrypt_buffer(&ctx, hexarray, (size_t) data_length);

    if (LOG_DEBUG) {
        printf("----- decrypted start -----\n");
        for (int i = 0; i < data_length; ++i) {
            printf("%02x", hexarray[i]);
        }
        printf("\n----- decrypted end -----\n");
    }

    int pad_count = pkcs7_padding_un_pad_count(hexarray, data_length);
    if (-1 == pad_count) {
        free(hexarray);
        return NULL;
    }
    int count = data_length - pad_count;
    if (LOG_DEBUG) {
        printf("remove padding after : %02x : %d\n", pad_count, count);
    }

    uint8_t *outarray = (uint8_t *) malloc(count);
    if (outarray == NULL) {
        free(hexarray);
        return NULL;
    }
    memset(outarray, 0, count);
    memcpy(outarray, hexarray, count);

    jbyteArray new_array = jni_env->NewByteArray(count);
    if (new_array == NULL) {
        free(outarray);
        free(hexarray);
        return NULL;
    }
    jni_env->SetByteArrayRegion(new_array, 0, count, (jbyte *) outarray);

    printf("----- decrypted %s, header : ", name);
    int limit = count < 8 ? count : 8;
    for (int i = 0; i < limit; ++i) {
        printf("%02x ", outarray[i]);
    }
    printf("-----\n");

    free(outarray);
    free(hexarray);

    return new_array;
}

static bool g_helper_bound = false;

static jbyteArray JNICALL
native_maybe_decrypt(JNIEnv *env, jclass /*clazz*/, jbyteArray jbuf, jint offset) {
    if (jbuf == nullptr) {
        return nullptr;
    }
    jsize len = env->GetArrayLength(jbuf);
    if (offset < 0 || offset > len) {
        return jbuf;
    }
    if (len - offset < 4) {
        return jbuf;
    }

    jbyte *data = env->GetByteArrayElements(jbuf, nullptr);
    if (!data) {
        return jbuf;
    }

    // 如果已经是 CAFEBABE，说明是明文 class，直接返回原数组
    if ((unsigned char) data[offset] == 0xCA &&
        (unsigned char) data[offset + 1] == 0xFE &&
        (unsigned char) data[offset + 2] == 0xBA &&
        (unsigned char) data[offset + 3] == 0xBE) {
        if (LOG_DEBUG) {
            printf("maybeDecrypt: already CAFEBABE, skip decrypt\n");
        }
        env->ReleaseByteArrayElements(jbuf, data, JNI_ABORT);
        return jbuf;
    }

    // 拷出 [offset, len) 作为密文部分
    size_t enc_len = (size_t) (len - offset);
    uint8_t *enc = (uint8_t *) malloc(enc_len);
    if (!enc) {
        env->ReleaseByteArrayElements(jbuf, data, JNI_ABORT);
        return jbuf;
    }
    memcpy(enc, (uint8_t *) data + offset, enc_len);
    env->ReleaseByteArrayElements(jbuf, data, JNI_ABORT);

    // 用与 decrypt 相同的逻辑解密
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, AES_IV);
    AES_CBC_decrypt_buffer(&ctx, enc, enc_len);

    int pad_count = pkcs7_padding_un_pad_count(enc, enc_len);
    if (pad_count == -1) {
        if (LOG_DEBUG) {
            printf("maybeDecrypt: invalid padding, fallback\n");
        }
        free(enc);
        return jbuf;
    }
    size_t plain_len = enc_len - pad_count;
    if (plain_len < 4) {
        if (LOG_DEBUG) {
            printf("maybeDecrypt: plain too short, fallback\n");
        }
        free(enc);
        return jbuf;
    }

    // 检查明文是否以 CAFEBABE 开头
    if (enc[0] != 0xCA || enc[1] != 0xFE ||
        enc[2] != 0xBA || enc[3] != 0xBE) {
        if (LOG_DEBUG) {
            printf("maybeDecrypt: not CAFEBABE after decrypt, fallback\n");
        }
        free(enc);
        return jbuf;
    }

    // 构造新的 byte[] 返回明文
    jbyteArray jout = env->NewByteArray((jsize) plain_len);
    if (!jout) {
        free(enc);
        return jbuf;
    }
    env->SetByteArrayRegion(jout, 0, (jsize) plain_len, (jbyte *) enc);
    free(enc);

    if (LOG_DEBUG) {
        printf("maybeDecrypt: decrypted to CAFEBABE, len=%d\n", (int) plain_len);
    }

    return jout;
}

static void try_bind_NativeDecryptHelper(JavaVM *vm) {
    if (g_helper_bound) {
        return;
    }

    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        printf("WARN: try_bind_NativeDecryptHelper: GetEnv failed\n");
        return;
    }

    jclass helperClazz = env->FindClass("com/github/jsbxyyx/mjar/NativeDecryptHelper");
    if (helperClazz == NULL) {
        // 类尚未加载，稍后在 ClassFileLoadHook 中再尝试
        if (LOG_DEBUG) {
            printf("INFO: NativeDecryptHelper not yet loaded\n");
        }
        return;
    }

    JNINativeMethod methods[] = {
        {
            const_cast<char *>("maybeDecrypt"),
            const_cast<char *>("([BI)[B"),
            (void *) &native_maybe_decrypt
        }
    };

    if (env->RegisterNatives(helperClazz, methods, 1) != 0) {
        printf("ERROR: RegisterNatives for NativeDecryptHelper.maybeDecrypt failed\n");
        return;
    }

    g_helper_bound = true;
    printf("INFO: NativeDecryptHelper.maybeDecrypt bound successfully\n");
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
static jvmtiEnv *m_pJvmTI = NULL;
static JavaVM *g_vm = NULL;

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
    if (!g_helper_bound && name != NULL) {
        if (strcmp(name, "com/github/jsbxyyx/mjar/NativeDecryptHelper") == 0) {
            if (g_vm != NULL) {
                try_bind_NativeDecryptHelper(g_vm);
            }
        }
    }

    if (name != NULL && (strcmp(name, "org/springframework/asm/ClassReader") == 0
                 || strcmp(name, "org/objectweb/asm/ClassReader") == 0)) {
        printf("--- [JVMTI] ClassFileLoadHook: %s\n", name);
    }

    if (name != NULL && strstr(name, pkg) != NULL) {
        printf("--- [JVMTI] ClassFileLoadHook: %s\n", name);
    }
    if (name != NULL && strstr(name, pkg) != NULL && strstr(name, "CGLIB$$") == NULL) {
        printf("--- decrypt class %s\n", name);

        // *new_class_data_len = class_data_len;
        // jvmti_env->Allocate(class_data_len, new_class_data);
        // unsigned char *my_data = *new_class_data;
        //
        // for (int i = 0; i < class_data_len; i++) {
        //     my_data[i] = class_data[i];
        // }
        // decrypt((char *) my_data);

        jbyteArray array = decrypt(jni_env, name, (unsigned char *) class_data, class_data_len);
        if (array == NULL) {
            *new_class_data_len = class_data_len;
            jvmti_env->Allocate(class_data_len, new_class_data);
            unsigned char *my_data = *new_class_data;
            memcpy(my_data, class_data, class_data_len);
            return;
        }
        jsize array_size = jni_env->GetArrayLength(array);
        jbyte *input = jni_env->GetByteArrayElements(array, 0);
        if (array_size < 4 ||
            (unsigned char) input[0] != 0xCA ||
            (unsigned char) input[1] != 0xFE ||
            (unsigned char) input[2] != 0xBA ||
            (unsigned char) input[3] != 0xBE) {
            printf("WARN: decrypted class %s is not CAFEBABE, fallback to original.\n", name);

            jni_env->ReleaseByteArrayElements(array, input, 0);
            jni_env->DeleteLocalRef(array);

            *new_class_data_len = class_data_len;
            jvmti_env->Allocate(class_data_len, new_class_data);
            unsigned char *my_data = *new_class_data;
            memcpy(my_data, class_data, class_data_len);
            return;
        }
        *new_class_data_len = array_size;
        jvmti_env->Allocate(array_size, new_class_data);
        unsigned char *my_data = *new_class_data;
        for (int i = 0; i < array_size; i++) {
            my_data[i] = input[i];
        }
        jni_env->ReleaseByteArrayElements(array, input, 0);
        jni_env->DeleteLocalRef(array);
    } else {
        *new_class_data_len = class_data_len;
        jvmti_env->Allocate(class_data_len, new_class_data);
        unsigned char *my_data = *new_class_data;
        memcpy(my_data, class_data, class_data_len);
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
        return JNI_ERR;
    }

    m_pJvmTI = jvmti;
    g_vm = vm;

    pkg = strdup(options);
    printf("--- options %s\n", options);

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
