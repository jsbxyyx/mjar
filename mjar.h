// mjar.h
#ifndef MJAR_MJAR_H
#define MJAR_MJAR_H

#include "jvmti.h"
#include "jni.h"

// JVM 通过回调该方法启动 Agent
JNIEXPORT jint JNICALL
Agent_OnLoad(JavaVM *vm,
             char *options,
             void *reserved);

#endif //MJAR_MJAR_H