
#include<stdio.h>
#include<stdlib.h>
#include "aes_const.h"
#include "aes.h"



unsigned int *Encryption(unsigned int *state, unsigned int *exp_key, int round) {
    int i = 0;

    /* Initial round add round key  */
    state = AddRoundKey(state, exp_key, i);

    /* Every round run four step  */
    for (i = 1; i < round; i++) {
        state = SubBytes(state);
        state = ShiftRow(state);
        state = MixColumns(state);
        state = AddRoundKey(state, exp_key, i);
    }

    /* Last round only run three step */
    state = SubBytes(state);
    state = ShiftRow(state);
    state = AddRoundKey(state, exp_key, i);

    return state;

}

unsigned int *Decryption(unsigned int *state, unsigned int *exp_key, int round) {
    int i = round;

    /* Initial round only run three step */
    state = AddRoundKey(state, exp_key, i);
    state = InvShiftRow(state);
    state = InvSubBytes(state);


    /* Every round run four step  */
    for (i = round - 1; i > 0; i--) {
        state = AddRoundKey(state, exp_key, i);
        state = InvMixColumns(state);
        state = InvShiftRow(state);
        state = InvSubBytes(state);
    }

    /* Last round add round key  */
    state = AddRoundKey(state, exp_key, i);

    return state;

}

unsigned int *ShiftLeft(unsigned int *exp_key) {
    *exp_key = (*exp_key & (((unsigned int) 0xff) << 24)) >> 24 |
               (*exp_key & (((unsigned int) 0xff) << 16)) << 8 |
               (*exp_key & (((unsigned int) 0xff) << 8)) << 8 |
               (*exp_key & (((unsigned int) 0xff))) << 8;

    return exp_key;
}

unsigned int *KeyExpansion(unsigned char *inp_key, unsigned int *exp_key, int number_keys, int round) {
    unsigned int *tmp;
    tmp = (unsigned int *) malloc(sizeof(unsigned int));

    /* Initial first round key state exp_key[0:key_len] */
    for (int i = 0; i < number_keys; i++) {
        exp_key[i] = (unsigned int) inp_key[0 + 4 * i] << 24 |
                     (unsigned int) inp_key[1 + 4 * i] << 16 |
                     (unsigned int) inp_key[2 + 4 * i] << 8 |
                     (unsigned int) inp_key[3 + 4 * i];
    }

    /* Expansion round key  */
    for (int i = number_keys; i < 4 * (round + 1); i++) {
        *tmp = exp_key[i - 1];

        if (i % number_keys == 0) {
            tmp = ShiftLeft(tmp);
            *tmp = S_BOX[*tmp >> 24] << 24 |
                   S_BOX[*tmp >> 16 & 0xff] << 16 |
                   S_BOX[*tmp >> 8 & 0xff] << 8 |
                   S_BOX[*tmp & 0xff];

            *tmp = *tmp ^ (R_CON[i / number_keys] << 24);
        }
        else if (number_keys > 6 && i % number_keys == 4) {
            *tmp = S_BOX[*tmp >> 24] << 24 |
                   S_BOX[*tmp >> 16 & 0xff] << 16 |
                   S_BOX[*tmp >> 8 & 0xff] << 8 |
                   S_BOX[*tmp & 0xff];
        }
        exp_key[i] = exp_key[i - number_keys] ^ (*tmp);
    }

    return exp_key;

}

void PrintExpansionKey(unsigned int *exp_key) {
    int i;
    printf("round: 0\n");
    for (i = 0; i < 44; i++) {
        if (i % 4 == 0 && i != 0) {
            printf("\n");
            printf("round: %d\n", i / 4);
        }
        printf("%08x\n", exp_key[i]);
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
        b[2] = (state[i] >> 8) & (unsigned int) 0xff;
        b[3] = (state[i]) & (unsigned int) 0xff;


        d[0] = (gmul2[b[0]] & 0xff) ^ (gmul3[b[1]] & 0xff) ^ (b[2] & 0xff)        ^ (b[3] & 0xff);
        d[1] = (b[0] & 0xff)        ^ (gmul2[b[1]] & 0xff) ^ (gmul3[b[2]] & 0xff) ^ (b[3] & 0xff);
        d[2] = (b[0] & 0xff)        ^ (b[1] & 0xff)        ^ (gmul2[b[2]] & 0xff) ^ (gmul3[b[3]] & 0xff);
        d[3] = (gmul3[b[0]] & 0xff) ^ (b[1] & 0xff)        ^ (b[2] & 0xff)        ^ (gmul2[b[3]] & 0xff);


        s[i] = d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3];
    }

    state[0] = s[0];
    state[1] = s[1];
    state[2] = s[2];
    state[3] = s[3];

    return state;
}

unsigned int *AddRoundKey(unsigned int *state, unsigned int *exp_key, int round) {
    int i;
    for (i = round * 4; i < (round * 4) + 4; i++) {
        state[i % 4] ^= exp_key[i];
    }

    return state;
}


unsigned int *InvSubBytes(unsigned int *state) {
    int i;
    for (i = 0; i < 4; i++) {
        state[i] = invS_BOX[state[i] >> 24] << 24 |
                   invS_BOX[state[i] >> 16 & 0xff] << 16 |
                   invS_BOX[state[i] >> 8 & 0xff] << 8 |
                   invS_BOX[state[i] & 0xff];
    }

    return state;
}

unsigned int *InvShiftRow(unsigned int *state) {
    unsigned int *s;
    s = (unsigned int *) malloc(sizeof(unsigned int) * 4);
    s[0] = state[0] & (0xff << 24) | state[3] & (0xff << 16) | state[2] & (0xff << 8) | state[1] & (0xff);
    s[1] = state[1] & (0xff << 24) | state[0] & (0xff << 16) | state[3] & (0xff << 8) | state[2] & (0xff);
    s[2] = state[2] & (0xff << 24) | state[1] & (0xff << 16) | state[0] & (0xff << 8) | state[3] & (0xff);
    s[3] = state[3] & (0xff << 24) | state[2] & (0xff << 16) | state[1] & (0xff << 8) | state[0] & (0xff);

    state[0] = s[0];
    state[1] = s[1];
    state[2] = s[2];
    state[3] = s[3];

    return state;
}

unsigned int *InvMixColumns(unsigned int *state) {
    int i;
    unsigned int *s, *b, *d;
    s = (unsigned int *) malloc(sizeof(unsigned int) * 4);
    b = (unsigned int *) malloc(sizeof(unsigned int) * 4);
    d = (unsigned int *) malloc(sizeof(unsigned int) * 4);

    for (i = 0; i < 4; i++) {
        b[0] = (state[i] >> 24);
        b[1] = (state[i] >> 16) & (unsigned int) 0xff;
        b[2] = (state[i] >> 8) & (unsigned int) 0xff;
        b[3] = (state[i]) & (unsigned int) 0xff;


        d[0] = (gmul14[b[0]] & 0xff) ^ (gmul11[b[1]] & 0xff) ^ (gmul13[b[2]] & 0xff) ^ (gmul9[b[3]] & 0xff);
        d[1] = (gmul9[b[0]] & 0xff)  ^ (gmul14[b[1]] & 0xff) ^ (gmul11[b[2]] & 0xff) ^ (gmul13[b[3]] & 0xff);
        d[2] = (gmul13[b[0]] & 0xff) ^ (gmul9[b[1]] & 0xff)  ^ (gmul14[b[2]] & 0xff) ^ (gmul11[b[3]] & 0xff);
        d[3] = (gmul11[b[0]] & 0xff) ^ (gmul13[b[1]] & 0xff) ^ (gmul9[b[2]] & 0xff)  ^ (gmul14[b[3]] & 0xff);


        s[i] = d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3];
    }

    state[0] = s[0];
    state[1] = s[1];
    state[2] = s[2];
    state[3] = s[3];

    return state;
}
