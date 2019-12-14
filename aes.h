

#ifndef AES_AES_H
#define AES_AES_H

unsigned int *Encryption(unsigned int *state, unsigned int *exp_key, int round);

unsigned int *Decryption(unsigned int *state, unsigned int *exp_key, int round);

unsigned int *ShiftLeft(unsigned int *exp_key);

unsigned int *KeyExpansion(unsigned char inp_key[], unsigned int *exp_key, int number_keys, int round);

void PrintExpansionKey(unsigned int *exp_key);

void PrintState(unsigned int *state);

unsigned int *SubBytes(unsigned int *state);

unsigned int *ShiftRow(unsigned int *state);

unsigned int *MixColumns(unsigned int *state);

unsigned int *AddRoundKey(unsigned int *state, unsigned int *exp_key, int round);

unsigned int *InvSubBytes(unsigned int *state);

unsigned int *InvShiftRow(unsigned int *state);

unsigned int *InvMixColumns(unsigned int *state);

#endif //AES_AES_H
