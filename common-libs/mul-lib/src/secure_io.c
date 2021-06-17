/*
 * secure_io.c - Provides security I/O apis
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "secure_io.h"

/**
 * Create an 256 bit key and IV using the supplied key_data.
 * Ssalt can be added for taste. Fills in the encryption and decryption ctx
 * Returns 0 on success
 **/
int
sec_io_aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt,
                EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
    int i, nrounds = 5;
    unsigned char key[32], iv[32];
  
    /*
    * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the 
    * supplied key material. nrounds is the number of times the we hash 
    * the material. More rounds are more secure but slower
    */
    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data,
                       key_data_len, nrounds, key, iv);
    if (i != 32) {
        printf("Key size is %d bits - should be 256 bits\n", i);
        return -1;
    }

    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

    return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *
sec_io_aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
    /* max ciphertext len for a n bytes of plaintext is 
    * n + AES_BLOCK_SIZE -1 bytes 
    */
    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = malloc(c_len);

    /* allows reusing of 'e' for multiple encryption cycles */
    EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

    /* update ciphertext, c_len is filled with the length of ciphertext
     * generated, len is the size of plaintext in bytes */
    EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

    /* update ciphertext with the final remaining bytes */
    EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

    *len = c_len + f_len;
    return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *
sec_io_aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* Because we have padding ON, we must allocate an extra cipher block 
   * size of memory */
    int p_len = *len, f_len = 0;
    unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);
  
    EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
    EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

    *len = p_len + f_len;
    return plaintext;
}

int
sec_file_write(FILE *fp, EVP_CIPHER_CTX *en, void *info, int len)
{
    void *cipher;

    if (!fp) {
        return -1;
    }

    cipher = sec_io_aes_encrypt(en, (unsigned char *)info, &len);
    if (cipher && len) {
        fwrite(cipher, len, 1, fp);
        free(cipher);
    } else {
        return -1;
    }

    return len;
}

int
sec_file_read(FILE *fp, EVP_CIPHER_CTX *de, void *info, int buf_len)
{
    void *cipher;
    void *plain = NULL;
    int len = buf_len < CIPHER_LEN ? CIPHER_LEN : buf_len;
    int ret = 0;

    if (!fp) {
        printf("Cant find file \n"); 
        return -1;
    }

    cipher = calloc(1, len);
    ret = fread(cipher, len, 1, fp);
    if (ret <= 0) goto out;
    plain = (char *)sec_io_aes_decrypt(de, cipher, &len);
    if (plain && len) {
        memcpy(info, plain, buf_len);
        free(plain);
        ret = len;
    } else {
        ret = -1;
    }
out:
    free(cipher);
    return ret;
}
