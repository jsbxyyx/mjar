#include "pkcs7_padding.h"

int pkcs7_padding_add_padding(uint8_t *data, size_t data_padded_length, size_t data_length) {
    int code = data_padded_length - data_length;
    size_t index = data_length;
    while (index < data_padded_length) {
        data[index] = (uint8_t) code;
        index++;
    }
    return code;
}

int pkcs7_padding_un_pad_count(uint8_t *data, size_t data_length) {
    int count_val = data[data_length - 1];
    int count = count_val & 0xFF;
    int position = data_length - count;

    int failed = (position | (count - 1)) >> 31;
    for (int i = 0; i < data_length; ++i) {
        failed |= (data[i] ^ count_val) & ~((i - position) >> 31);
    }
    if (failed != 0) {
        return -1;
    }
    return count;
}

uint8_t pkcs7_padding_pad_count(size_t data_length, uint8_t block_size) {
    uint8_t padding_length = block_size - (data_length % block_size);
    return padding_length;
}
