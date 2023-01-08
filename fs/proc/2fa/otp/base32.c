/*
 *
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2017, fmount <fmount9@autistici.org>
 *
 *  This software is distributed under MIT License
 *
 *  Compute the hmac using openssl library.
 *  SHA-1 engine is used by default, but you can pass another one,
 *
 *  e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
 *
 */
#include <linux/vmalloc.h>
#include "base32.h"

static int
check_input(const unsigned char* user_data, size_t data_len, int max_len)
{
    if (user_data == NULL || (data_len == 0 && user_data[0] != '\0')) {
        return -1;
    } else if (user_data[0] == '\0') {
        return -1;
    }

    if (data_len > max_len) {
        return -1;
    }

    return 0;
}

static const int8_t base32_vals[256] = {
    //    This map cheats and interprets:
    //       - the numeral zero as the letter "O" as in oscar
    //       - the numeral one as the letter "L" as in lima
    //       - the numeral eight as the letter "B" as in bravo
    // 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
    14, 11, 26, 27, 28, 29, 30, 31,  1, -1, -1, -1, -1,  0, -1, -1, // 0x30
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x40
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 0x50
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x60
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1, // 0x70
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};


int
validate_b32key(char *k, size_t len)
{
    size_t pos;
    // validates base32 key
    if (((len & 0xF) != 0) && ((len & 0xF) != 8))
        return 1;
    for (pos = 0; (pos < len); pos++) {
        if (base32_vals[(int)k[pos]] == -1)
            return 1;
        if (k[pos] == '=') {
            if (((pos & 0xF) == 0) || ((pos & 0xF) == 8))
                return(1);
            if ((len - pos) > 6)
                return 1;
            switch (pos % 8) {
            case 2:
            case 4:
            case 5:
            case 7:
                break;
            default:
                return 1;
            }
            for ( ; (pos < len); pos++) {
                if (k[pos] != '=')
                    return 1;
            }
        }
    }
    return 0;
}

// The encoding process represents 40-bit groups of input bits as output strings of 8 encoded characters. The input data must be null terminated.
char *
base32_encode(const unsigned char *user_data, size_t data_len)
{
    static const unsigned char b32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    int error;
    size_t user_data_chars, total_bits, output_length;
    int num_of_equals;
    int i, j;
    uint64_t first_octet, second_octet, third_octet, fourth_octet, fifth_octet;
    uint64_t quintuple;
    char *encoded_data;

    user_data_chars = 0;
    total_bits = 0;
    num_of_equals = 0;
    error = check_input(user_data, data_len, MAX_ENCODE_INPUT_LEN);
    if (error != 0) {
        return NULL;
    }

    for (i = 0; i < data_len; i++) {
        // As it's not known whether data_len is with or without the +1 for the null byte, a manual check is required.
        // Check for null byte only at the end of the user given length, otherwise issue#23 may occur
        if (user_data[i] == '\0' && i == data_len-1) {
            break;
        } else {
            total_bits += 8;
            user_data_chars += 1;
        }
    }
    switch (total_bits % 40) {
        case 8:
            num_of_equals = 6;
            break;
        case 16:
            num_of_equals = 4;
            break;
        case 24:
            num_of_equals = 3;
            break;
        case 32:
            num_of_equals = 1;
            break;
        default:
            break;
    }

    output_length = (user_data_chars * 8 + 4) / 5;
    encoded_data = vmalloc(output_length + num_of_equals + 1);
    memset(encoded_data,0,output_length + num_of_equals + 1);
    if (encoded_data == NULL) {
        return NULL;
    }

    for (i = 0, j = 0; i < user_data_chars;) {
        first_octet = i < user_data_chars ? user_data[i++] : 0;
        second_octet = i < user_data_chars ? user_data[i++] : 0;
        third_octet = i < user_data_chars ? user_data[i++] : 0;
        fourth_octet = i < user_data_chars ? user_data[i++] : 0;
        fifth_octet = i < user_data_chars ? user_data[i++] : 0;
        quintuple =
                ((first_octet >> 3) << 35) +
                ((((first_octet & 0x7) << 2) | (second_octet >> 6)) << 30) +
                (((second_octet & 0x3F) >> 1) << 25) +
                ((((second_octet & 0x01) << 4) | (third_octet >> 4)) << 20) +
                ((((third_octet & 0xF) << 1) | (fourth_octet >> 7)) << 15) +
                (((fourth_octet & 0x7F) >> 2) << 10) +
                ((((fourth_octet & 0x3) << 3) | (fifth_octet >> 5)) << 5) +
                (fifth_octet & 0x1F);

        encoded_data[j++] = b32_alphabet[(quintuple >> 35) & 0x1F];
        encoded_data[j++] = b32_alphabet[(quintuple >> 30) & 0x1F];
        encoded_data[j++] = b32_alphabet[(quintuple >> 25) & 0x1F];
        encoded_data[j++] = b32_alphabet[(quintuple >> 20) & 0x1F];
        encoded_data[j++] = b32_alphabet[(quintuple >> 15) & 0x1F];
        encoded_data[j++] = b32_alphabet[(quintuple >> 10) & 0x1F];
        encoded_data[j++] = b32_alphabet[(quintuple >> 5) & 0x1F];
        encoded_data[j++] = b32_alphabet[(quintuple >> 0) & 0x1F];
    }
    
    for (i = 0; i < num_of_equals; i++) {
        encoded_data[output_length + i] = '=';
    }
    encoded_data[output_length + num_of_equals] = '\0';

    return encoded_data;
}

size_t
decode_b32key(uint8_t **k, size_t len)
{

    size_t keylen;
    size_t pos;
    // decodes base32 secret key
    keylen = 0;
    for (pos = 0; pos <= (len - 8); pos += 8) {
    // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
    // MB is middle bits             (0x7E == 01111110 ~= MB)
    // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)

    // byte 0
    (*k)[keylen+0]  = (base32_vals[(*k)[pos+0]] << 3) & 0xF8; // 5 MSB
    (*k)[keylen+0] |= (base32_vals[(*k)[pos+1]] >> 2) & 0x07; // 3 LSB
    if ((*k)[pos+2] == '=') {
        keylen += 1;
        break;
    }

    // byte 1
    (*k)[keylen+1]  = (base32_vals[(*k)[pos+1]] << 6) & 0xC0; // 2 MSB
    (*k)[keylen+1] |= (base32_vals[(*k)[pos+2]] << 1) & 0x3E; // 5  MB
    (*k)[keylen+1] |= (base32_vals[(*k)[pos+3]] >> 4) & 0x01; // 1 LSB
    if ((*k)[pos+4] == '=') {
        keylen += 2;
        break;
    }

    // byte 2
    (*k)[keylen+2]  = (base32_vals[(*k)[pos+3]] << 4) & 0xF0; // 4 MSB
    (*k)[keylen+2] |= (base32_vals[(*k)[pos+4]] >> 1) & 0x0F; // 4 LSB
    if ((*k)[pos+5] == '=') {
        keylen += 3;
        break;
    }

    // byte 3
    (*k)[keylen+3]  = (base32_vals[(*k)[pos+4]] << 7) & 0x80; // 1 MSB
    (*k)[keylen+3] |= (base32_vals[(*k)[pos+5]] << 2) & 0x7C; // 5  MB
    (*k)[keylen+3] |= (base32_vals[(*k)[pos+6]] >> 3) & 0x03; // 2 LSB
    if ((*k)[pos+7] == '=') {
        keylen += 4;
        break;
    }

    // byte 4
    (*k)[keylen+4]  = (base32_vals[(*k)[pos+6]] << 5) & 0xE0; // 3 MSB
    (*k)[keylen+4] |= (base32_vals[(*k)[pos+7]] >> 0) & 0x1F; // 5 LSB
    keylen += 5;
    }
    (*k)[keylen] = 0;

    return keylen;
}
