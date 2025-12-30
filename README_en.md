# mjar

[中文](README.md) 英文

`mjar` is a **JVMTI agent + JNI library** that works together with [mjar-java](https://github.com/jsbxyyx/mjar-java) to:

- Encrypt Java class bytecode (AES‑CBC + PKCS#7) on build time via JNI.
- Decrypt and load encrypted classes at JVM runtime via a JVMTI `ClassFileLoadHook`.
- Optionally bind a native `maybeDecrypt([BI)[B` method to patched ASM `ClassReader` classes.

Typical usage (see [`readme.txt`](readme.txt)):

```bat
%JAVA_HOME%\bin\java.exe -jar mjar.jar io/github/jsbxyyx testjar.jar

%JAVA_HOME%\bin\java.exe -agentpath:./libmjar.dll=io/github/jsbxyyx -jar testjar-enc.jar
```

---

## How It Works

### Components

- **Native shared library** `mjar` (`libmjar.{dll,so,dylib}`):
  - Implements:
    - `Java_com_github_jsbxyyx_mjar_Mjarencrypt_encrypt` – JNI entry used by `mjar-java` to encrypt class bytes.
    - `Agent_OnLoad` – JVMTI agent entry point.
    - `JNI_OnLoad` – JNI library entry point.
  - Uses:
    - `AES` (CBC mode) from `aes.c`
    - `PKCS#7` padding (`pkcs7_padding.c`)
    - `SHA1` (`sha1.c`) to derive AES key from a secret
    - Utility helpers (`stringutils.c`)

- **Header** [`com_github_jsbxyyx_mjar_Mjarencrypt.h`](com_github_jsbxyyx_mjar_Mjarencrypt.h)  
  Machine-generated JNI header for the Java class `com.github.jsbxyyx.mjar.Mjarencrypt` in [mjar-java](https://github.com/jsbxyyx/mjar-java).

- **Agent callbacks** (in [`mjar.cpp`](mjar.cpp)):
  - `CallbackClassFileLoadHook`  
    Intercepts class loading, attempts to decrypt encrypted class bytes, and replaces them if decryption succeeds and the result looks like a valid `CAFEBABE` class file.
  - `OnClassPrepare`  
    When certain `ClassReader` classes are prepared (e.g. `org/springframework/asm/ClassReader`), binds a native method:
    ```c++
    JNINativeMethod methods[] = {
        { "maybeDecrypt", "([BI)[B", (void *)&native_maybe_decrypt }
    };
    ```
    This allows patched ASM `ClassReader` (from `mjar-java`) to call into native decryption logic.

---

## Key Management

By default, `AES_KEY` and `AES_IV` are defined in `mjar.cpp`:

```c++
static unsigned char AES_KEY[16] = { 0x00, 0x01, ..., 0x0f };
static unsigned char AES_IV[16]  = { 0x00, 0x00, ..., 0x00 };
```

At runtime, the key can be overridden using an external secret file:

```c++
static bool load_key_from_env() {
    const char *path = getenv("MJAR_SECRET_PATH");
    if (path == NULL) {
        fprintf(stderr, "--- [MJAR] Error: Environment variable MJAR_SECRET_PATH not found.\n");
        return false;
    }
    FILE *fp = fopen(path, "r");
    ...
    // 1. Read secret text from file
    // 2. Compute SHA1
    // 3. Use first 16 bytes as AES_KEY
}
```

- Set environment variable `MJAR_SECRET_PATH` to point to a secret file.
- The secret is read once on `Agent_OnLoad` / `JNI_OnLoad`, hashed with SHA‑1, and the first 16 bytes are used as AES key.
- Buffer holding the plain secret is wiped after use.

Optional debug logging can be enabled with:

```sh
MJAR_LOG_DEBUG=1
```

---

## JVMTI Agent Flow

From [`mjar.h`](mjar.h):

```c
JNIEXPORT jint JNICALL
Agent_OnLoad(JavaVM *vm,
             char *options,
             void *reserved);
```

In [`mjar.cpp`](mjar.cpp):

1. **Agent_OnLoad**

   - Gets `jvmtiEnv` via `vm->GetEnv(JVMTI_VERSION_1_1)`.
   - Calls `load_key_from_env()` (if `MJAR_SECRET_PATH` is configured).
   - Stores:
     - `m_pJvmTI` – global `jvmtiEnv *`
     - `g_vm` – global `JavaVM *`
   - Saves `options` (agent argument) into global `pkg`:
     ```c++
     pkg = strdup(options);
     printf("--- options %s\n", options);
     ```
     This string usually holds the **target package prefix** (e.g. `io/github/jsbxyyx`) from:
     ```bat
     -agentpath:./libmjar.dll=io/github/jsbxyyx
     ```
   - Requests JVMTI capabilities (`can_generate_all_class_hook_events`, `can_tag_objects`, etc.).
   - Registers callbacks:
     - `ClassFileLoadHook = CallbackClassFileLoadHook`
     - `ClassPrepare = OnClassPrepare`
   - Enables:
     - `JVMTI_EVENT_CLASS_FILE_LOAD_HOOK`
     - `JVMTI_EVENT_CLASS_PREPARE`

2. **CallbackClassFileLoadHook**

   - Called on every class load.
   - If the class belongs to the encrypted package, calls native `decrypt(...)`.
   - Validates first 4 bytes for `0xCA, 0xFE, 0xBA, 0xBE`:
     ```c++
     if (array_size < 4 ||
         (unsigned char) input[0] != 0xCA ||
         (unsigned char) input[1] != 0xFE ||
         (unsigned char) input[2] != 0xBA ||
         (unsigned char) input[3] != 0xBE) {
         printf("WARN: decrypted class %s is not CAFEBABE, fallback to original.\n", name);
         ...
     }
     ```
   - If invalid, falls back to original class bytes.

3. **OnClassPrepare**

   - Checks class signature via `GetClassSignature`.
   - For ASM `ClassReader`-like classes (signature ends with `/asm/ClassReader;` but not in JDK packages), registers native `maybeDecrypt([BI)[B` using `RegisterNatives`.

4. **JNI_OnLoad**

   - Also calls `load_key_from_env()` to ensure AES key is set when the library is loaded as a pure JNI lib (without agent).

---

## Encryption / Decryption

### Encryption (JNI, used by mjar-java)

`Java_com_github_jsbxyyx_mjar_Mjarencrypt_encrypt(JNIEnv*, jobject, jbyteArray)`:

- Pads input bytes with PKCS#7.
- Encrypts with AES-CBC using current `AES_KEY` + `AES_IV`.
- Optionally logs the first bytes if `MJAR_LOG_DEBUG` is set.
- Returns a new `jbyteArray` containing encrypted data.

### Decryption (Agent, at class load)

`decrypt(JNIEnv *jni_env, const char *name, unsigned char *data, size_t data_length)`:

- Copies input bytes.
- Performs AES-CBC decryption with current key.
- Removes PKCS#7 padding.
- Returns a new `jbyteArray` with decrypted class bytes.

`native_maybe_decrypt` is used as a hook for ASM-patched `ClassReader`:

```c++
static jbyteArray JNICALL
native_maybe_decrypt(JNIEnv *env, jclass clazz, jbyteArray jbuf, jint offset) {
    // decides whether to decrypt, and if so, calls decrypt(...)
}
```

---

## Build

This is a C/C++ project using CMake and JNI.

### Prerequisites

- CMake ≥ 3.15
- C/C++ toolchain (e.g. MSVC, clang, gcc)
- JDK with JNI headers

### Configure & Build

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

CMake will:

- Find Java + JNI:

  ```cmake
  find_package(Java REQUIRED COMPONENTS Development)
  find_package(JNI REQUIRED)
  ```

- Build shared library:

  ```cmake
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

Result:

- `libmjar.so` (Linux)
- `libmjar.dylib` (macOS)
- `mjar.dll` (Windows)

---

## Usage with mjar-java

1. **Encrypt classes** with [mjar-java](https://github.com/jsbxyyx/mjar-java) via JNI:

   ```bat
   %JAVA_HOME%\bin\java.exe -jar mjar.jar io/github/jsbxyyx testjar.jar
   ```

   This calls into `Java_com_github_jsbxyyx_mjar_Mjarencrypt_encrypt`.

2. **Run the encrypted jar** with JVMTI agent:

   ```bat
   %JAVA_HOME%\bin\java.exe -agentpath:./libmjar.dll=io/github/jsbxyyx -jar testjar-enc.jar
   ```

   - `libmjar.dll` is the shared library built from this repo.
   - `io/github/jsbxyyx` is passed to the agent as `options` (`pkg`), used to decide which classes to treat as encrypted.

For more details about the Java‑side encryption and class patching, see [mjar-java](https://github.com/jsbxyyx/mjar-java).

---

## Security Notes

- Do **not** commit your real secret to the repository.
- Use `MJAR_SECRET_PATH` to point to a secure location containing the secret text.
- The secret is hashed with SHA‑1 and reduced to 16 bytes for AES‑128 key; memory containing the plain secret is cleared after use.
- This project aims to raise the bar for reverse engineering, not to provide unbreakable protection.

---

## License

See the repository for licensing details (add a `LICENSE` file if appropriate).
