#include<stdio.h>
#include<stdlib.h>
#include "aes.h"

unsigned int *Encryption(unsigned int *state, unsigned int *exp_key, int round);
unsigned int *Decryption(unsigned int *state, unsigned int *exp_key, int round);

int main(void) {
    int i;
    int round = 10;
    unsigned char inp_16_bytes[16] = "0000000000000000";

    char inp_key[16] = "0000000000000000";
    unsigned int *state;
    unsigned int *exp_key;

    state = (unsigned int *) malloc(sizeof(unsigned int) * 4);
    exp_key = (unsigned int *) malloc(sizeof(unsigned int) * 44);


//    scanf("%s", &inp_16_bytes);
//    scanf("%s",&inp_key);

    exp_key = KeyExpansion(inp_key, exp_key);
//    PrintExpansionKey(exp_key);


    // initial state
    for (i = 0; i < 4; i++) {
        state[i] = (unsigned int) inp_16_bytes[0 + 4 * i] << 24 |
                   (unsigned int) inp_16_bytes[1 + 4 * i] << 16 |
                   (unsigned int) inp_16_bytes[2 + 4 * i] << 8  |
                   (unsigned int) inp_16_bytes[3 + 4 * i];
    }

    printf("Initial state:\n");
    PrintState(state);

    /* Initial round add round key  */
    state = AddRoundKey(state, exp_key, 0);
    printf("Add key0:\n");
    PrintState(state);

    printf("\nr %d:\n",0);
    state = SubBytes(state);
    printf("subbyte\n");
    PrintState(state);
    printf("\n");

    state = ShiftRow(state);
    printf("shift\n");
    PrintState(state);
    printf("\n");

    state = MixColumns(state);
    printf("mix\n");
    PrintState(state);
    printf("\n");

    state = AddRoundKey(state, exp_key, 1);
    printf("a\n");
    PrintState(state);
    printf("\n");


    state = Encryption(state, exp_key, round);
    printf("Encryption state:\n");
    PrintState(state);

    state = Decryption(state, exp_key, round);
    printf("Decryption state:\n");
    PrintState(state);

    free(state);
    free(exp_key);

    return 0;
}

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
    state = ShiftRow(state);
    state = SubBytes(state);


    /* Every round run four step  */
    for (i = round - 1; i > 0; i--) {
        state = AddRoundKey(state, exp_key, i);
        state = MixColumns(state);
        state = ShiftRow(state);
        state = SubBytes(state);
    }

    /* Last round add round key  */
    state = AddRoundKey(state, exp_key, i);

    return state;

}