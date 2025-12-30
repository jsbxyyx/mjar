# mjar

中文 [英文](README_en.md)

`mjar` 是一个基于 **JVMTI Agent + JNI** 的原生库，用于配合 [mjar-java](https://github.com/jsbxyyx/mjar-java) 实现：

- 在构建阶段对 Java class 字节码进行 **AES‑CBC + PKCS#7 加密**；
- 在 JVM 运行时通过 JVMTI `ClassFileLoadHook` 对加密的 class 进行 **按需解密与加载**；
- 通过在 ASM `ClassReader` 中注入并绑定原生 `maybeDecrypt([BI)[B` 方法，实现对特殊场景的解密支持。

典型使用方式（见 [`readme.txt`](readme.txt)）：

```bat
%JAVA_HOME%\bin\java.exe -jar mjar.jar io/github/jsbxyyx testjar.jar

%JAVA_HOME%\bin\java.exe -agentpath:./libmjar.dll=io/github/jsbxyyx -jar testjar-enc.jar
```

---

## 整体架构说明

本仓库主要是一个原生动态库（`libmjar.{dll,so,dylib}`），由 `C/C++ + JNI + JVMTI` 组成，主要能力包括：

1. **JNI 加密接口**

   - 暴露给 Java 侧（`mjar-java`）的 JNI 方法：

     ```c
     JNIEXPORT jbyteArray JNICALL
     Java_com_github_jsbxyyx_mjar_Mjarencrypt_encrypt(JNIEnv *, jobject, jbyteArray);
     ```

   - 该方法负责：
     1. 接收 Java 传入的 `byte[]`（class 字节码或任意数据）；
     2. 使用 PKCS#7 进行补齐；
     3. 使用 AES‑CBC 模式加密；
     4. 返回新的加密后 `byte[]`。

2. **JVMTI Agent**

   - 入口函数在 [`mjar.h`](mjar.h) 中定义：

     ```c
     JNIEXPORT jint JNICALL
     Agent_OnLoad(JavaVM *vm,
                  char *options,
                  void *reserved);
     ```

   - 在 `Agent_OnLoad` 中完成：
     - 通过 `vm->GetEnv` 获取 `jvmtiEnv`；
     - 从环境变量中加载密钥（`MJAR_SECRET_PATH`，见下文）；
     - 将 Agent 选项 `options` （通常是包前缀，如 `io/github/jsbxyyx`）保存在全局变量 `pkg` 中：
       ```c
       pkg = strdup(options);
       printf("--- options %s\n", options);
       ```
     - 注册 JVMTI 回调：
       - `ClassFileLoadHook` → `CallbackClassFileLoadHook`
       - `ClassPrepare` → `OnClassPrepare`
     - 开启相关 JVMTI 事件通知。

3. **Class 加载与解密流程**

   - `CallbackClassFileLoadHook`：
     - 在每个 class 加载时被调用；
     - 如果类名匹配目标包前缀 `pkg`，则尝试对字节码进行解密；
     - 解密后检查前 4 字节是否为 `CAFEBABE`：
       - 若是，则认为解密成功，用新字节替换；
       - 否则回退到原始字节码，避免破坏加载过程。

   - `OnClassPrepare`：
     - 通过 `GetClassSignature` 获取 class 的签名；
     - 当发现是 ASM `ClassReader` 类（如 `Lorg/springframework/asm/ClassReader;` / `Lorg/objectweb/asm/ClassReader;`），且不属于 JDK 自带包时：
       - 通过 `RegisterNatives` 为该类注册本地方法：
         ```c
         JNINativeMethod methods[] = {
             { "maybeDecrypt", "([BI)[B", (void *)&native_maybe_decrypt }
         };
         ```
       - 这样配合 `mjar-java` 中的 ASM 字节码补丁，可以让 `ClassReader` 在读取 class buffer 时调用 `maybeDecrypt`，实现对嵌套或特殊情况的二次解密。

---

## 加密 / 解密实现细节

### AES 加密（JNI 路径）

在 [`mjar.cpp`](mjar.cpp) 中，`encrypt` 函数大致逻辑如下：

1. 从 JNI 中获取 `jbyteArray` 内容和长度；
2. 使用 PKCS#7 填充到 AES 块大小（`AES_BLOCKLEN`）的整数倍；
3. 使用 `AES_CBC_encrypt_buffer` 以 AES‑CBC 模式进行加密；
4. 返回新的 `jbyteArray` 承载密文。

核心字段：

```c++
static unsigned char AES_KEY[16] = { 0x00, 0x01, ..., 0x0f };
static unsigned char AES_IV[16]  = { 0x00, 0x00, ..., 0x00 };
```

### AES 解密（Agent 路径）

- `decrypt(JNIEnv *jni_env, const char *name, unsigned char *data, size_t data_length)`：
  - 复制输入密文字节；
  - 使用同一 `AES_KEY` + `AES_IV` 进行 AES‑CBC 解密；
  - 去除 PKCS#7 填充；
  - 若明文头 4 字节为 `CAFEBABE`，则视为有效 class 文件。

- `native_maybe_decrypt(JNIEnv *env, jclass clazz, jbyteArray jbuf, jint offset)`：
  - 用于与 `ClassReader` 的字节码插桩配合：
    - 根据偏移 `offset` 决定是否尝试解密；
    - 若解密失败或结果不合法，则返回原数组；
    - 若解密成功且头为 `CAFEBABE`，返回新的明文字节数组。

---

## 密钥管理（MJAR_SECRET_PATH）

默认情况下，`AES_KEY` 是在代码中硬编码的一组测试密钥。为了实际部署，支持通过环境变量动态加载密钥：

```c
static bool load_key_from_env() {
    const char *path = getenv("MJAR_SECRET_PATH");
    if (path == NULL) {
        fprintf(stderr, "--- [MJAR] Error: Environment variable MJAR_SECRET_PATH not found.\n");
        return false;
    }
    FILE *fp = fopen(path, "r");
    ...
    // 读取一行字符串，计算 SHA1，并取前 16 字节作为 AES_KEY
}
```

流程：

1. 设置环境变量 `MJAR_SECRET_PATH` 指向某个只读的密钥文件；
2. `Agent_OnLoad` / `JNI_OnLoad` 启动时调用 `load_key_from_env()`：
   - 从文件读取一行字符串（密钥原文）；
   - 对该字符串做 SHA‑1；
   - 将前 16 字节复制到 `AES_KEY` 中；
   - 清空 buffer 内容，关闭文件，并清理环境变量（防止泄露）。

调试日志：

- 若设置了环境变量 `MJAR_LOG_DEBUG`（任意非空值），会在加解密过程中打印部分调试信息（如前几字节的 hex 值、padding 长度等）。

---

## 构建说明

本项目使用 CMake 管理构建，基于 JNI 和 JVMTI。

### 环境依赖

- CMake ≥ 3.15
- C / C++ 编译器（gcc / clang / MSVC 等）
- 安装 JDK，并确保：
  - `JAVA_HOME` 配置正确；
  - 可以找到 JNI 头文件与库。

### CMake 配置

核心配置见 [`CMakeLists.txt`](CMakeLists.txt)：

```cmake
cmake_minimum_required(VERSION 3.15)
project(mjar LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Java REQUIRED COMPONENTS Development)
find_package(JNI REQUIRED)

add_library(mjar SHARED
    mjar.cpp
    aes.c
    pkcs7_padding.c
    sha1.c
    stringutils.c
)

target_include_directories(mjar PRIVATE ${JNI_INCLUDE_DIRS})
target_link_libraries(mjar PRIVATE ${JNI_LIBRARIES})
```

#### 构建步骤示例

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

输出文件示例：

- Linux：`libmjar.so`
- macOS：`libmjar.dylib`
- Windows：`mjar.dll`（配合 `-agentpath:./mjar.dll=...` 使用）

---

## 与 mjar-java 的协同使用

1. **构建并获取 `libmjar` 动态库**

   按上述步骤编译本项目，得到 `libmjar` 对应的动态库文件。

2. **使用 [mjar-java](https://github.com/jsbxyyx/mjar-java) 对业务 JAR 加密**

   例如：

   ```bat
   %JAVA_HOME%\bin\java.exe -jar mjar.jar io/github/jsbxyyx xx-1.0.jar
   ```

   - 这里的 `mjar.jar` 是 Java 侧工具（`mjar-java` 打包后的 jar）；
   - 内部会通过 JNI 调用 `Java_com_github_jsbxyyx_mjar_Mjarencrypt_encrypt` 对指定包前缀下的 class 进行 AES 加密；
   - 输出结果为 `xx-1.0-enc.jar`。

3. **通过 Agent 运行加密后的 JAR**

   ```bat
   %JAVA_HOME%\bin\java.exe -agentpath:./libmjar.dll=io/github/jsbxyyx -jar xx-1.0-enc.jar
   ```

   - `-agentpath:./libmjar.dll=io/github/jsbxyyx`：
     - 告诉 JVM 加载当前目录下的 `libmjar.dll` 作为 Agent；
     - 将 `io/github/jsbxyyx` 作为 `Agent_OnLoad` 的 `options` 参数，用于过滤哪些包下的类需要尝试解密。
   - `-jar xx-1.0-enc.jar`：
     - 启动已加密的应用。

在运行过程中：

- JVMTI `ClassFileLoadHook` 会对匹配包前缀的 class 尝试使用 AES 解密；
- 若解密成功且 class 头为 `CAFEBABE`，则使用解密后的字节码替换；
- 配合 `mjar-java` 对 ASM `ClassReader` 的补丁和 `maybeDecrypt` 注册，可以进一步处理复杂场景（嵌套 class buffer 等）。

---

## 安全提示

- **不要** 将真实密钥硬编码在源码或提交到仓库中；
- 推荐使用 `MJAR_SECRET_PATH` 指向受控的密钥文件，仅在部署环境中存在；
- 本项目的目标是提升逆向工程门槛，而不是提供不可破解的安全机制：
  - 部署到客户端之后，攻击者始终可以通过调试、内存抓取等方式进行分析；
  - 建议将其与混淆、授权校验、服务器端校验等手段结合使用，形成多层防护。

---

## 相关项目

- [mjar-java](https://github.com/jsbxyyx/mjar-java)：Java 侧打包与 ASM 插桩工具，用于生成加密后的 JAR/WAR。
