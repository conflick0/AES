//
// Created by root on 2019/11/30.
//

#include "aes.h"


/* S-box */
unsigned int S_BOX[256] =  {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  //F
};

/* Round Constant */
unsigned int R_CON[11] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

unsigned int *ShiftLeft(unsigned int *exp_key) {
    unsigned int *tmp;
    tmp = (unsigned int *) malloc(sizeof(unsigned int));
    *tmp = (*exp_key & (((unsigned int) 0xff) << 24)) >> 24 |
           (*exp_key & (((unsigned int) 0xff) << 16)) << 8  |
           (*exp_key & (((unsigned int) 0xff) << 8)) << 8   |
           (*exp_key & (((unsigned int) 0xff))) << 8;
    return tmp;
}

unsigned int *KeyExpansion(char inp_key[], unsigned int *exp_key) {
    unsigned int *tmp;
    tmp = (unsigned int *) malloc(sizeof(unsigned int));

    /* Initial first round key state exp_key[0:4] */
    for (int i = 0; i < 4; i++) {
        exp_key[i] = (unsigned int) inp_key[0 + 4 * i] << 24 |
                     (unsigned int) inp_key[1 + 4 * i] << 16 |
                     (unsigned int) inp_key[2 + 4 * i] << 8  |
                     (unsigned int) inp_key[3 + 4 * i];
    }

    /* Expansion round key  */
    for (int i = 4; i < 44; i++) {
        *tmp = exp_key[i - 1];
        if (i % 4 == 0) {
            tmp = ShiftLeft(tmp);
            *tmp = S_BOX[*tmp >> 24] << 24        |
                   S_BOX[*tmp >> 16 & 0xff] << 16 |
                   S_BOX[*tmp >> 8 & 0xff] << 8   |
                   S_BOX[*tmp & 0xff];

            *tmp = *tmp ^ (R_CON[i / 4]<<24);
        }
        exp_key[i] = exp_key[i - 4] ^ (*tmp);
    }

    return exp_key;

}

void PrintExpansionKey(unsigned int *exp_key){
    int i;
    printf("round: 0\n");
    for (i = 0; i < 44; i++) {
        if(i%4==0&&i!=0){
            printf("\n");
            printf("round: %d\n",i/4);
        }
        printf("%08x\n",exp_key[i]);
    }
    printf("\n");

}

void PrintState(unsigned int *state) {
    int i;
    unsigned int *s;
    s = (unsigned int *) malloc(sizeof(unsigned int) * 4);

    // state row col reverse for easy to look
    s[0] = (state[0] & (0xff << 24))      | (state[1] & (0xff << 24)) >> 8 | (state[2] & (0xff << 24)) >> 16 | (state[3] & (0xff << 24)) >> 24;
    s[1] = (state[0] & (0xff << 16)) << 8 | (state[1] & (0xff << 16))      | (state[2] & (0xff << 16)) >> 8  | (state[3] & (0xff << 16)) >> 16;
    s[2] = (state[0] & (0xff << 8)) << 16 | (state[1] & (0xff << 8)) << 8  | (state[2] & (0xff << 8))        | (state[3] & (0xff << 8)) >> 8;
    s[3] = (state[0] & 0xff) << 24        | (state[1] & 0xff) << 16        | (state[2] & 0xff) << 8          | (state[3] & 0xff);

    for (i = 0; i < 4; i++) {
        printf("%02x %02x %02x %02x\n", s[i] >> 24, (s[i] >> 16) & 0xff, (s[i] >> 8) & 0xff, s[i] & 0xff);
    }
}

unsigned int *SubBytes(unsigned int *state) {
    int i;
    for (i = 0; i < 4; i++) {
        state[i] = S_BOX[state[i] >> 24] << 24 |
                   S_BOX[state[i] >> 16 & 0xff] << 16 |
                   S_BOX[state[i] >> 8 & 0xff] << 8 |
                   S_BOX[state[i] & 0xff];
    }

    return state;
}

unsigned int *ShiftRow(unsigned int *state) {
    unsigned int *s;
    s = (unsigned int *) malloc(sizeof(unsigned int) * 4);
    s[0] = state[0] & (0xff << 24) | state[1] & (0xff << 16) | state[2] & (0xff << 8) | state[3] & (0xff);
    s[1] = state[1] & (0xff << 24) | state[2] & (0xff << 16) | state[3] & (0xff << 8) | state[0] & (0xff);
    s[2] = state[2] & (0xff << 24) | state[3] & (0xff << 16) | state[0] & (0xff << 8) | state[1] & (0xff);
    s[3] = state[3] & (0xff << 24) | state[0] & (0xff << 16) | state[1] & (0xff << 8) | state[2] & (0xff);

    state[0] = s[0];
    state[1] = s[1];
    state[2] = s[2];
    state[3] = s[3];

    return state;
}

unsigned int *MixColumns(unsigned int *state) {
    int i;
    unsigned int *s, *b, *d;
    s = (unsigned int *) malloc(sizeof(unsigned int) * 4);
    b = (unsigned int *) malloc(sizeof(unsigned int) * 4);
    d = (unsigned int *) malloc(sizeof(unsigned int) * 4);

    for (i = 0; i < 4; i++) {
        b[0] = (state[i] >> 24);
        b[1] = (state[i] >> 16) & (unsigned int) 0xff;
        b[2] = (state[i] >> 8)  & (unsigned int) 0xff;
        b[3] = (state[i])       & (unsigned int) 0xff;


        d[0] = ((2 * b[0]) & (unsigned int) 0xff) ^ ((3 * b[1]) & (unsigned int) 0xff) ^ ((1 * b[2]) & (unsigned int) 0xff) ^ ((1 * b[3]) & (unsigned int) 0xff);
        d[1] = ((1 * b[0]) & (unsigned int) 0xff) ^ ((2 * b[1]) & (unsigned int) 0xff) ^ ((3 * b[2]) & (unsigned int) 0xff) ^ ((1 * b[3]) & (unsigned int) 0xff);
        d[2] = ((1 * b[0]) & (unsigned int) 0xff) ^ ((1 * b[1]) & (unsigned int) 0xff) ^ ((2 * b[2]) & (unsigned int) 0xff) ^ ((3 * b[3]) & (unsigned int) 0xff);
        d[3] = ((3 * b[0]) & (unsigned int) 0xff) ^ ((1 * b[1]) & (unsigned int) 0xff) ^ ((1 * b[2]) & (unsigned int) 0xff) ^ ((2 * b[3]) & (unsigned int) 0xff);

        s[i] = d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3];
    }

    state[0] = s[0];
    state[1] = s[1];
    state[2] = s[2];
    state[3] = s[3];

    return state;
}

unsigned int *AddRoundKey(unsigned int *state, unsigned int *exp_key,int round) {
    int i;
    for (i = round*4; i < (round*4)+4; i++) {
        state[i%4] ^= exp_key[i];
    }

    return state;
}






