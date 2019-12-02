//
// Created by root on 2019/11/30.
//

#ifndef AES_AES_H
#define AES_AES_H
#include<stdio.h>
#include<stdlib.h>
unsigned int* ShiftLeft(unsigned int* exp_key);
unsigned int* KeyExpansion(unsigned char inp_key[], unsigned int* exp_key);
void PrintExpansionKey(unsigned int *exp_key);
void PrintState(unsigned int *state);
unsigned int *SubBytes(unsigned int *state);
unsigned int *ShiftRow(unsigned int *state);
unsigned int *MixColumns(unsigned int *state);
unsigned int *AddRoundKey(unsigned int *state, unsigned int *exp_key,int round) ;
#endif //AES_AES_H
