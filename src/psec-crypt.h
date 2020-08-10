#ifndef PSEC_CRYPT_H
#define PSEC_CRYPT_H

#include "psec-crypt-options.h"

#ifdef TI84CE_BUILD
#include <tice.h>
#else
#ifdef LX_BUILD
#include <stdlib.h>
#define os_ClrHome() printf("\n")
#define os_GetStringInput(a, b, c) {printf(a); fgets(b, c, stdin);}
#define os_PutStrFull(a) printf(a)
#define os_GetCSC() 1
#endif
#endif
#include <stdio.h>
//#include <stdlib.h>

volatile unsigned char hex_enc[] = "0123456789ABCDEF";
//unsigned char hex_dec[16];

volatile unsigned char sbox_enc[] = {182, 145, 190, 136, 227, 154, 143, 246, 251, 91, 35, 139, 232, 40, 12, 84, 135, 24, 117, 233, 22, 165, 95, 219, 108, 55, 250, 60, 107, 198, 13, 170, 93, 26, 163, 188, 30, 171, 191, 195, 174, 149, 137, 238, 94, 54, 102, 37, 248, 197, 39, 142, 156, 224, 78, 68, 41, 209, 115, 116, 205, 131, 38, 206, 25, 208, 77, 100, 161, 192, 222, 247, 173, 85, 228, 252, 31, 33, 14, 196, 58, 71, 27, 146, 76, 141, 214, 210, 217, 103, 172, 64, 212, 244, 62, 121, 239, 82, 242, 32, 133, 223, 105, 112, 169, 15, 168, 126, 74, 151, 7, 202, 109, 106, 186, 114, 113, 72, 153, 3, 96, 80, 187, 226, 193, 90, 203, 123, 110, 138, 49, 51, 215, 207, 194, 213, 36, 134, 175, 245, 83, 127, 201, 119, 152, 132, 21, 216, 73, 220, 11, 29, 69, 56, 101, 118, 6, 130, 125, 221, 164, 230, 129, 144, 229, 158, 179, 181, 48, 10, 89, 17, 184, 180, 104, 140, 128, 87, 243, 185, 57, 42, 111, 19, 46, 157, 45, 160, 67, 166, 18, 53, 92, 255, 124, 183, 234, 122, 235, 236, 150, 75, 61, 178, 5, 2, 43, 63, 86, 16, 70, 88, 167, 200, 249, 0, 225, 189, 148, 59, 218, 79, 211, 120, 177, 1, 34, 240, 176, 99, 50, 204, 254, 98, 4, 159, 9, 8, 44, 147, 52, 97, 20, 65, 155, 66, 81, 23, 237, 253, 47, 162, 28, 241, 231, 199};
volatile unsigned char sbox_dec[] = {215, 225, 205, 119, 234, 204, 156, 110, 237, 236, 169, 150, 14, 30, 78, 105, 209, 171, 190, 183, 242, 146, 20, 247, 17, 64, 33, 82, 252, 151, 36, 76, 99, 77, 226, 10, 136, 47, 62, 50, 13, 56, 181, 206, 238, 186, 184, 250, 168, 130, 230, 131, 240, 191, 45, 25, 153, 180, 80, 219, 27, 202, 94, 207, 91, 243, 245, 188, 55, 152, 210, 81, 117, 148, 108, 201, 84, 66, 54, 221, 121, 246, 97, 140, 15, 73, 208, 177, 211, 170, 125, 9, 192, 32, 44, 22, 120, 241, 233, 229, 67, 154, 46, 89, 174, 102, 113, 28, 24, 112, 128, 182, 103, 116, 115, 58, 59, 18, 155, 143, 223, 95, 197, 127, 194, 158, 107, 141, 176, 162, 157, 61, 145, 100, 137, 16, 3, 42, 129, 11, 175, 85, 51, 6, 163, 1, 83, 239, 218, 41, 200, 109, 144, 118, 5, 244, 52, 185, 165, 235, 187, 68, 251, 34, 160, 21, 189, 212, 106, 104, 31, 37, 90, 72, 40, 138, 228, 224, 203, 166, 173, 167, 0, 195, 172, 179, 114, 122, 35, 217, 2, 38, 69, 124, 134, 39, 79, 49, 29, 255, 213, 142, 111, 126, 231, 60, 63, 133, 65, 57, 87, 222, 92, 135, 86, 132, 147, 88, 220, 23, 149, 159, 70, 101, 53, 216, 123, 4, 74, 164, 161, 254, 12, 19, 196, 198, 199, 248, 43, 96, 227, 253, 98, 178, 93, 139, 7, 71, 48, 214, 26, 8, 75, 249, 232, 193};

volatile unsigned char pbox_enc[] = {4, 7, 15, 6, 14, 8, 2, 0, 12, 1, 11, 3, 10, 5, 13, 9};
volatile unsigned char pbox_dec[] = {7, 9, 6, 11, 0, 13, 3, 1, 5, 15, 12, 10, 8, 14, 4, 2};

//volatile unsigned char pbox_enc[] = {11, 16, 21, 6, 57, 10, 23, 8, 3, 5, 30, 38, 7, 46, 58, 33, 54, 9, 55, 1, 49, 41, 4, 13, 53, 17, 56, 39, 47, 20, 63, 59, 15, 48, 29, 12, 60, 35, 18, 42, 50, 61, 44, 36, 26, 0, 31, 14, 45, 22, 24, 25, 51, 37, 40, 19, 2, 52, 27, 28, 62, 43, 34, 32};
//volatile unsigned char pbox_dec[] = {45, 19, 56, 8, 22, 9, 3, 12, 7, 17, 5, 0, 35, 23, 47, 32, 1, 25, 38, 55, 29, 2, 49, 6, 50, 51, 44, 58, 59, 34, 10, 46, 63, 15, 62, 37, 43, 53, 11, 27, 54, 21, 39, 61, 42, 48, 13, 28, 33, 20, 40, 52, 57, 24, 16, 18, 26, 4, 14, 31, 36, 41, 60, 30};

#define _8BITS 0b11111111

#define MOD_BLK_SIZE ((1 << BLK_SIZE_BITS) - 1)
#define MOD_KEY_SIZE ((1 << KEY_SIZE_BITS) - 1)
#define MSG_SIZE  (MOD_BLK_SIZE + 1)
#define KEY_SIZE  (MOD_KEY_SIZE + 1)

/* Set maximum size of input and output buffers */
#define BLK_SIZE  MSG_SIZE
#define EXP_KEY_SIZE (BLK_SIZE * ROUNDS)
#define HASH_ITERS 1

#define KEY_IN_SIZE (KEY_SIZE * 2 + 2)
#define MSG_IN_SIZE (MSG_SIZE * 2 + 2)


/* define worker functions */
#define ROLS(x, n, s) ((x << (n)) ^ (x >> (s - (n))))
#define RORS(x, n, s) ((x >> (n)) ^ (x << (s - (n))))
#define ROL(x, n) ROLS(x, n, 8)
#define ROR(x, n) RORS(x, n, 8)

void round_enc_sub(volatile unsigned char *msg, volatile unsigned char *key){
	size_t a;
	for(a=0; a<MSG_SIZE; ++a){
		msg[a] = sbox_enc[msg[a]];
		msg[a] ^= key[a];
	}
}
void round_dec_sub(volatile unsigned char *msg, volatile unsigned char *key){
	size_t a;
	for(a=0; a<MSG_SIZE; ++a){
		msg[a] ^= key[a];
		msg[a] = sbox_dec[msg[a]];
	}
}
void round_mix(volatile unsigned char *msg, volatile unsigned char *key, volatile unsigned char *tmp){
	size_t a;
	unsigned char b;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	for(a=0; a<MSG_SIZE; ++a){
		tmp[a] = msg[a];
	}
	for(a=0; a<MSG_SIZE; a += 2){
		b = msg[a];
		c = msg[(a + 1) & MOD_BLK_SIZE];
		d = (b & 0b10101010) | (c & 0b01010101);
		e = (b & 0b01010101) | (c & 0b10101010);
		msg[a] = d;
		msg[(a + 1) & MOD_BLK_SIZE] = e;
	}
}
void round_enc_per(volatile unsigned char *msg, volatile unsigned char *key, volatile unsigned char *tmp){
	size_t a;
	unsigned char b = key[0] & MOD_BLK_SIZE;
	for(a=0; a<MSG_SIZE; ++a){
		tmp[a] = msg[a];
	}
	for(a=0; a<MSG_SIZE; ++a){
		msg[pbox_enc[a ^ b]] = tmp[a];
	}
}
void round_dec_per(volatile unsigned char *msg, volatile unsigned char *key, volatile unsigned char *tmp){
	size_t a;
	unsigned char b = key[0] & MOD_BLK_SIZE;
	for(a=0; a<MSG_SIZE; ++a){
		tmp[a] = msg[a];
	}
	for(a=0; a<MSG_SIZE; ++a){
		msg[pbox_dec[a] ^ b] = tmp[a];
	}
}
void round_enc(volatile unsigned char *msg, volatile unsigned char *key, volatile unsigned char *tmp){
	round_enc_sub(msg, key);
	round_enc_per(msg, key, tmp);
	round_mix(msg, key, tmp);
}
void round_dec(volatile unsigned char *msg, volatile unsigned char *key, volatile unsigned char *tmp){
	round_mix(msg, key, tmp);
	round_dec_per(msg, key, tmp);
	round_dec_sub(msg, key);
}
void enc(volatile unsigned char *msg, volatile unsigned char *exp_key, volatile unsigned char *tmp){
	size_t a;
	for(a=0; a<ROUNDS; ++a){
		round_enc(msg, &exp_key[a * MSG_SIZE], tmp);
	}
}
void dec(volatile unsigned char *msg, volatile unsigned char *exp_key, volatile unsigned char *tmp){
	size_t a;
	for(a=ROUNDS; a>0; --a){
		round_dec(msg, &exp_key[(a-1) * MSG_SIZE], tmp);
	}
}

void expand_key(volatile unsigned char *key, volatile unsigned char *exp_key){
	size_t a;
	size_t b;
	for(a=0; a<EXP_KEY_SIZE; ++a){
		exp_key[a] = a;
	}
	for(a=0; a<ROUNDS; ++a){
		for(b=0; b<KEY_SIZE; ++b){
			//os_ClrHome();
//			os_PutStrFull(text);
			exp_key[a * MSG_SIZE + (sbox_enc[b ^ a ^ ROUNDS] & MOD_BLK_SIZE)] ^= sbox_enc[key[(b ^ sbox_enc[a]) & MOD_KEY_SIZE] ^ sbox_dec[a] ^ b ^ KEY_SIZE];
		}
	}
}
volatile void encrypt(volatile unsigned char *msg, volatile unsigned char *key){
	unsigned char exp_key[EXP_KEY_SIZE];
	unsigned char tmp[MSG_SIZE];
//	char text[16];
	size_t a;
	size_t b;
	expand_key(key, exp_key);
	enc(msg, exp_key, tmp);
	for(a=0; a<KEY_SIZE; ++a){
		key[a] = 0;
	}
	for(a=0; a<MSG_SIZE; ++a){
		tmp[a] = 0;
		for(b=0; b<ROUNDS; ++b){
			//os_ClrHome();
			//os_PutStrFull(text);
			exp_key[b * MSG_SIZE + a] = 0;
		}
	}
}
volatile void decrypt(volatile unsigned char *msg, volatile unsigned char *key){
	volatile unsigned char exp_key[EXP_KEY_SIZE];
	volatile unsigned char tmp[MSG_SIZE];
//	char text[16];
	size_t a;
	size_t b;
	expand_key(key, exp_key);
	dec(msg, exp_key, tmp);
	for(a=0; a<KEY_SIZE; ++a){
		key[a] = 0;
	}
	for(a=0; a<MSG_SIZE; ++a){
		tmp[a] = 0;
		for(b=0; b<ROUNDS; ++b){
			//os_ClrHome();
			//os_PutStrFull(text);
			exp_key[b * MSG_SIZE + a] = 0;
		}
	}
}
unsigned char hex_to_int(unsigned char c){
        unsigned char first = c / 16 - 3;
        unsigned char second = c % 16;
        unsigned char result = first*10 + second;
        if(result > 9) result--;
        return result;
}

void to_hex(unsigned char *input, unsigned char *output, const size_t size){
	size_t a;
	for(a=0; a<size; ++a){
		output[a * 2] = hex_enc[input[a] / 16];
		output[a * 2 + 1] = hex_enc[input[a] % 16];
		output[a * 2 + 2] = 0;
	}
}
void from_hex(unsigned char *input, unsigned char *output, const size_t size){
	size_t a;
	for(a=0; a<size; ++a){
		output[a] = hex_to_int(input[a * 2]) * 16;
		output[a] += hex_to_int(input[a * 2 + 1]);
	}
}
void hash_key(unsigned char *key){
	unsigned char exp_key[MSG_SIZE * ROUNDS];
	
}
void nop(unsigned char *key){
	// NOP
}


#endif
