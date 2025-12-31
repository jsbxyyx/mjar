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
#include "sha1.hpp"
#include "stringutils.hpp"

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
        int limit = data_length < 8 ? data_length : 8;
        for (int i = 0; i < limit; ++i) {
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
        int limit = data_padded_length < 8 ? data_padded_length : 8;
        for (int i = 0; i < limit; ++i) {
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
        int limit = data_length < 8 ? data_length : 8;
        for (int i = 0; i < limit; ++i) {
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

    free(outarray);
    free(hexarray);

    return new_array;
}

static jbyteArray JNICALL
native_maybe_decrypt(JNIEnv *env, jclass clazz, jbyteArray jbuf, jint offset) {
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

static void JNICALL CallbackClassFileLoadHook(jvmtiEnv *jvmti_env,
                                              JNIEnv *jni_env,
                                              jclass class_being_redefined,
                                              jobject loader,
                                              const char *name,
                                              jobject protection_domain,
                                              jint class_data_len,
                                              const unsigned char *class_data,
                                              jint *new_class_data_len,
                                              unsigned char **new_class_data) {
    if (name != NULL && stringutils_endswith(name, "/asm/ClassReader")) {
        printf("--- ClassFileLoadHook: %s\n", name);
    }

    if (LOG_DEBUG) {
        if (name != NULL && stringutils_startswith(pkg, name)) {
            printf("--- ClassFileLoadHook: %s\n", name);
        }
    }
    if (name != NULL && stringutils_startswith(pkg, name)
        && strstr(name, "CGLIB$$") == NULL
        && strstr(name, "$$Lambda$") == NULL) {
        printf("--- decrypt class %s\n", name);

        if (class_being_redefined != NULL) {
            fprintf(stdout, "--- Security Alert: Blocking [%s]\n", name);
            static unsigned char poison_bytecode[] = {};
            *new_class_data_len = sizeof(poison_bytecode);
            jvmti_env->Allocate(*new_class_data_len, new_class_data);
            memcpy(*new_class_data, poison_bytecode, *new_class_data_len);
            return;
        }

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

static void JNICALL OnClassPrepare(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread, jclass klass) {
    char *signature;
    if (jvmti_env->GetClassSignature(klass, &signature, NULL) == JVMTI_ERROR_NONE) {
        // 注意：Lorg/springframework/asm/ClassReader; 是标准的 JVM 签名格式
        if (signature != NULL && stringutils_endswith(signature, "/asm/ClassReader;")) {
            // 排除 jdk 签名
            if (!(
                stringutils_startswith("Ljava/", signature) ||
                stringutils_startswith("Ljavax/", signature) ||
                stringutils_startswith("Lsun/", signature) ||
                stringutils_startswith("Lcom/sun/", signature) ||
                stringutils_startswith("Ljdk/", signature) ||
                stringutils_startswith("Lorg/w3c/dom/", signature) ||
                stringutils_startswith("Lorg/xml/sax/", signature) ||
                stringutils_startswith("Lorg/ietf/", signature) ||
                stringutils_startswith("Lnetscape/javascript/", signature)
            )) {
                JNINativeMethod methods[] = {
                    {(char *) "maybeDecrypt", (char *) "([BI)[B", (void *) &native_maybe_decrypt}
                };
                if (jni_env->RegisterNatives(klass, methods, 1) == 0) {
                    printf("--- Native method bound to [%s]\n", signature);
                } else {
                    printf("--- ERROR: RegisterNatives failed\n");
                }
            } else {
                printf("--- Native method not bound to [%s]\n", signature);
            }
        }
        jvmti_env->Deallocate((unsigned char *) signature);
    }
}

static bool load_key_from_env() {
    const char *path = getenv("MJAR_SECRET_PATH");
    if (path == NULL) {
        fprintf(stderr, "--- [MJAR] Error: Environment variable MJAR_SECRET_PATH not found.\n");
        return false;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return false;
    }
    setvbuf(fp, NULL, _IONBF, 0);
    bool is_new_key = false;
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\r\n")] = 0;

        sha1nfo s;
        sha1_init(&s);
        sha1_write(&s, buffer, strlen(buffer));
        uint8_t *hash_result = sha1_result(&s);
        memcpy(AES_KEY, hash_result, 16);

        memset(buffer, 0, sizeof(buffer));
        is_new_key = true;
    }
    fclose(fp);
#ifdef _WIN32
    _putenv_s("MJAR_SECRET_PATH", "");
#else
    unsetenv("MJAR_SECRET_PATH");
#endif
    return is_new_key;
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
    printf("--- [MJAR] Agent_OnLoad\n");

    m_pJvmTI = jvmti;
    g_vm = vm;

    if (load_key_from_env()) {
        fprintf(stdout, "--- [MJAR] Secret loaded from file and purged.\n");
    }

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
    callbacks.ClassPrepare = &OnClassPrepare;

    error = jvmti->SetEventCallbacks(&callbacks, (jint) sizeof(callbacks));
    if (error != JVMTI_ERROR_NONE) {
        printf("ERROR: Unable to SetEventCallbacks JVMTI!\n");
        return error;
    }

    // For each of the above callbacks, enable this event.
    error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_PREPARE, (jthread) NULL);
    if (error != JVMTI_ERROR_NONE) {
        printf("ERROR: Unable to SetEventNotificationMode JVMTI_EVENT_CLASS_PREPARE JVMTI!\n");
        return error;
    }

    error = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                                            JVMTI_EVENT_CLASS_FILE_LOAD_HOOK,
                                            (jthread) NULL);
    if (error != JVMTI_ERROR_NONE) {
        printf("ERROR: Unable to SetEventNotificationMode JVMTI_EVENT_CLASS_FILE_LOAD_HOOK JVMTI!\n");
        return error;
    }

    return JNI_OK;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    printf("--- [MJAR] JNI_OnLoad\n");

    if (load_key_from_env()) {
        fprintf(stdout, "--- [MJAR] Secret loaded from file and purged.\n");
    }

    return JNI_VERSION_1_8;
}
