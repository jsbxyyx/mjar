#ifndef PKCS7_PADDING_H
#define PKCS7_PADDING_H

#include <stdint.h>
#include <stddef.h>

int pkcs7_padding_add_padding(uint8_t *data, size_t data_padded_length, size_t data_length);

int pkcs7_padding_un_pad_count(uint8_t *data, size_t data_length);

uint8_t pkcs7_padding_pad_count(size_t data_length, uint8_t block_size);

#endif //PKCS7_PADDING_H
