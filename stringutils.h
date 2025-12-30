#ifndef STRINGUTILS_H
#define STRINGUTILS_H

#include <stdbool.h>

bool stringutils_startswith(const char *pre, const char *str);

bool stringutils_endswith(const char *str, const char *suffix);

#endif //STRINGUTILS_H
