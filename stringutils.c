#include <stddef.h>
#include <string.h>
#include "stringutils.h"

bool stringutils_startswith(const char *prefix, const char *str) {
    if (prefix == NULL || str == NULL) {
        return false;
    }
    while (*prefix) {
        if (*str == '\0' || *prefix != *str) {
            return false;
        }
        prefix++;
        str++;
    }
    return true;
}

bool stringutils_endswith(const char *str, const char *suffix) {
    if (str == NULL || suffix == NULL) return false;
    size_t n = strlen(str);
    size_t m = strlen(suffix);
    if (m > n) return false;
    return memcmp(str + n - m, suffix, m) == 0;
}