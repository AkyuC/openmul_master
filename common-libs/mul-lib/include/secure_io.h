/*
 * secure_io.h - Secure I/O function definitions 
 * Copyright (C) 2012-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef __C_SECURE_IO_H__
#define __C_SECURE_IO_H__

#include <openssl/evp.h>
#include <openssl/aes.h>

#define CIPHER_LEN 32

int sec_io_aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt,
             EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);
unsigned char *sec_io_aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);
unsigned char *sec_io_aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);
int sec_file_write(FILE *fp, EVP_CIPHER_CTX *en, void *info, int len);
int sec_file_read(FILE *fp, EVP_CIPHER_CTX *de, void *info, int buf_len);

#endif
