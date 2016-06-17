//
//  aesctr.c
//  AES256CTRDemo
//
//  Created by Thỏ on 6/17/16.
//  Copyright © 2016 Thỏ. All rights reserved.
//

#include "aesctr.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>




int getLength(int* value)
{
    return sizeof(value) * sizeof(int);
}

int sBox[] = { 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

int rCon[][4] = { {0x00, 0x00, 0x00, 0x00},
    {0x01, 0x00, 0x00, 0x00},
    {0x02, 0x00, 0x00, 0x00},
    {0x04, 0x00, 0x00, 0x00},
    {0x08, 0x00, 0x00, 0x00},
    {0x10, 0x00, 0x00, 0x00},
    {0x20, 0x00, 0x00, 0x00},
    {0x40, 0x00, 0x00, 0x00},
    {0x80, 0x00, 0x00, 0x00},
    {0x1b, 0x00, 0x00, 0x00},
    {0x36, 0x00, 0x00, 0x00} };

/**
 * Rotate 4-byte word w left by one byte
 * @private
 */
int* rotWord (int* w) {
    int tmp = w[0];
    for (int i=0; i<3; i++) w[i] = w[i+1];
    w[3] = tmp;
    return w;
};

/**
 * Apply SBox to 4-byte word w
 * @private
 */
int* subWord(int* w){
    for (int i=0; i<4; i++) w[i] = sBox[w[i]];
    return w;
};

/**
 * Xor Round Key into state S [§5.1.4]
 * @private
 */
int** addRoundKey(int** state, int** w, int rnd, int Nb) {
    for (int r=0; r<4; r++) {
        for (int c=0; c<Nb; c++) state[r][c] ^= w[rnd*4+c][r];
    }
    return state;
};

/**
 * Combine bytes of each col of state S [§5.1.3]
 * @private
 */
int** mixColumns(int** s, int Nb) {
    for (int c=0; c<4; c++) {
        int a[4];  // 'a' is a copy of the current column from 's'
        int b[4];  // 'b' is a•{02} in GF(2^8)
        for (int i=0; i<4; i++) {
            a[i] = s[i][c];
            b[i] = s[i][c]&0x80 ? s[i][c]<<1 ^ 0x011b : s[i][c]<<1;
        }
        // a[n] ^ b[n] is a•{03} in GF(2^8)
        s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]; // {02}•a0 + {03}•a1 + a2 + a3
        s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]; // a0 • {02}•a1 + {03}•a2 + a3
        s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]; // a0 + a1 + {02}•a2 + {03}•a3
        s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]; // {03}•a0 + a1 + a2 + {02}•a3
    }
    return s;
};

/**
 * Shift row r of state S left by r bytes [§5.1.2]
 * @private
 */
int** shiftRows(int** s, int Nb) {
    int t[4];
    for (int r=1; r<4; r++) {
        for (int c=0; c<4; c++) t[c] = s[r][(c+r)%Nb];  // shift into temp copy
        for (int c=0; c<4; c++) s[r][c] = t[c];         // and copy back
    }          // note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
    return s;  // see asmaes.sourceforge.net/rijndael/rijndaelImplementation.pdf
};

/**
 * Apply SBox to state S [§5.1.1]
 * @private
 */
int** subBytes(int** s, int Nb) {
    for (int r=0; r<4; r++) {
        for (int c=0; c<Nb; c++) s[r][c] = sBox[s[r][c]];
    }
    return s;
};

/**
 * Perform key expansion to generate a key schedule from a cipher key [§5.2].
 *
 * @param   {number[]}   key - Cipher key as 16/24/32-byte array.
 * @returns {number[][]} Expanded key schedule as 2D byte-array (Nr+1 x Nb bytes).
 */
int** keyExpansion(int* key) {
    int Nb = 4;            // block size (in words): no of columns in state (fixed at 4 for AES)
    int Nk = getLength(key)/4; // key length (in words): 4/6/8 for 128/192/256-bit keys
    int Nr = Nk + 6;       // no of rounds: 10/12/14 for 128/192/256-bit keys
    
    int row =Nb*(Nr+1), column = 4;
    int **wKey = (int **)malloc(row * sizeof(int *));
    // for (int i=0; i<row; i++)
    //  wKey[i] = (int *)malloc(column * sizeof(int));
    
    int* temp = (int *)malloc(sizeof(int)*4);
    
    // initialise first Nk words of expanded key with cipher key
    for (int i=0; i<Nk; i++) {
        wKey[i] = (int *)malloc(column * sizeof(int));
        int r[4]  = {key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]};
        for (int j =0; j< 4; j++) {
            wKey[i][j] = r[j];
        }
    }
    
    // expand the key into the remainder of the schedule
    for (int i=Nk; i<(Nb*(Nr+1)); i++) {
        wKey[i] = (int *)malloc(column * sizeof(int));
        for (int t=0; t<4; t++) temp[t] = wKey[i-1][t];
        // each Nk'th word has extra transformation
        if (i % Nk == 0) {
            temp = subWord(rotWord(temp));
            for (int t=0; t<4; t++) temp[t] ^= rCon[i/Nk][t];
        }
        // 256-bit key has subWord applied every 4th word
        else if (Nk > 6 && i%Nk == 4) {
            temp = subWord(temp);
        }
        // xor w[i] with w[i-1] and w[i-Nk]
        for (int t=0; t<4; t++) wKey[i][t] = wKey[i-Nk][t] ^ temp[t];
    }
    // free(wKey);
    return wKey;
};

/**
 * AES Cipher function: encrypt 'input' state with Rijndael algorithm [§5.1];
 *   applies Nr rounds (10/12/14) using key schedule w for 'add round key' stage.
 *
 * @param   {number[]}   input - 16-byte (128-bit) input state array.
 * @param   {number[][]} w - Key schedule as 2D byte-array (Nr+1 x Nb bytes).
 * @returns {number[]}   Encrypted output state array.
 */
int* cipher(int* input,int** w,int length) {
    int Nb = 4;               // block size (in words): no of columns in state (fixed at 4 for AES)
    // int length = 60;//TODO w.length
    int Nr = length/Nb - 1; // no of rounds: 10/12/14 for 128/192/256-bit keys
    
    //var state = [[],[],[],[]];  // initialise 4xNb byte-array 'state' with input [§3.4]
    int **state = (int **)malloc(4 * sizeof(int *));
    for (int i=0; i<4; i++)
        state[i] = (int *)malloc(4 * sizeof(int));
    
    for (int i=0; i<4*Nb; i++)
        state[i%4][(int)floor(i/4)] = input[i];
    
    state = addRoundKey(state, w, 0, Nb);
    
    for (int round=1; round<Nr; round++) {
        state = subBytes(state, Nb);
        state = shiftRows(state, Nb);
        state = mixColumns(state, Nb);
        state = addRoundKey(state, w, round, Nb);
    }
    
    state = subBytes(state, Nb);
    state = shiftRows(state, Nb);
    state = addRoundKey(state, w, Nr, Nb);
    
    int* output=(int *)malloc(sizeof(int)*(4*Nb)); //malloc((4*Nb)*sizeof(int));//var output = new Array(4*Nb);  // convert state to 1-d array before returning [§3.4]
    
    for (int i=0; i<4*Nb; i++) output[i] = state[i%4][(int)floor(i/4)];
    
    ///free(state);
    // free(output);
    return output;
};

void subString(char* source,char* dest, int index, int size)
{
    dest =(char *)malloc(sizeof(char)*(size+ 1));
     memcpy( dest, &source[index], size);
     dest[index+size]= '\0';
}


void decryptAES(char* result,char* ciphertext, char* password){
    int nBits = 256;

    int lenCipher = (int)strlen(ciphertext);
    int lenPass = (int)strlen(password);
    
    int blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
    if (!(nBits==128 || nBits==192 || nBits==256))
    {
        //throw new Error('Key size is not 128 / 192 / 256');
    }
    //TODO  password = String(password).utf8Encode();
    
    // use AES to encrypt password (mirroring encrypt routine)
    int nBytes = nBits/8;  // no bytes in key
    int* pwBytes= (int *)malloc(sizeof(int)*nBytes);
    for (int i=0; i<nBytes; i++) {
        pwBytes[i] = i<lenPass ? (int) password[i] : 0;
    }
    int length = 60;
    int* key = cipher(pwBytes, keyExpansion(pwBytes), length);
    
    int* newKey= (int *)malloc(sizeof(int)*nBytes);
    newKey = key;
    for (int i = 0; i< (nBytes-16); i++) {
        newKey[16+ i] = key[i];
    }
    
    // recover nonce from 1st 8 bytes of ciphertext
    int *counterBlock=(int *)malloc(sizeof(int)*16);
    char* ctrTxt;
    subString(ciphertext, ctrTxt, 0, 8);
   
    for (int i =0; i<8; i++) {
        counterBlock[i] = (int) ctrTxt[i];
    }
    
    // generate key schedule
    int** keySchedule = keyExpansion(newKey);
    
    // separate ciphertext into blocks (skipping past initial 8 bytes)
    float valueCeil =(float) (lenCipher-8) / blockSize;
    int nBlocks = ceil(valueCeil);
   // char *ct =[[NSMutableArray alloc] initWithCapacity:nBlocks]; //new Array(nBlocks);
    char **ct = (char **)malloc(nBlocks * sizeof(char *));
    
    for (int b = 0; b < nBlocks; b++)
    {
        // ct[b] = (char *)malloc(blockSize * sizeof(char));
        int start = 8 + b * blockSize;
        int end = 8 + b * blockSize + blockSize;
        if (end >lenCipher)
             subString(ciphertext, ct[b], start, lenCipher -start);
           // [ct addObject:[ciphertext substringWithRange:NSMakeRange(start, lenCipher -start)]];
        else
            subString(ciphertext, ct[b], start, end - start);
           // [ct addObject:[ciphertext substringWithRange:NSMakeRange(start, end - start)]];
    }
    
    char* plaintext=(char *)malloc(sizeof(char)*nBlocks);
    
    for (int b=0; b<nBlocks; b++) {
        
        // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
        for (int c=0; c<4; c++)
            counterBlock[15-c] = ((b) >> c*8) & 0xff;
        for (int c=0; c<4; c++)
        {
            //   counterBlock[15-c-4] = (((b+1)/0x100000000-1) >> c*8) & 0xff;
            counterBlock[15-c-4] =0;
        }
        
        int* cipherCntr = cipher(counterBlock, keySchedule,60);  // encrypt counter block
        
        //NSString *ctItem = [ct objectAtIndex:b];
        int lenCt =(int)strlen(ct[b]);// (int)[ctItem length];
        char* plaintxtByte= (char *)malloc(sizeof(char)*(lenCt+1));
        //int i=0;
        for (int i=0; i<lenCt; i++) {
            // -- xor plaintext with ciphered counter byte-by-byte --
            int xorValue = cipherCntr[i] ^ (int) ct[b][i];
            plaintxtByte[i] = (char) xorValue;
        }
        plaintxtByte[lenCt]= '\0';
        strcat(plaintext, plaintxtByte);
    }
    
    result = plaintext;
   // NSLog(@"%s", plaintext);
    
  //  NSString *result1 =  [NSString stringWithCString:plaintext encoding:NSUTF8StringEncoding];
    
  //  NSLog(@"%@", result1);
    // free(pwBytes);
}
