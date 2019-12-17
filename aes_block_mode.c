

#include<stdio.h>
#include<stdlib.h>
#include "aes_block_mode.h"
#include "aes.h"

Block* ECB_Mode_Encryption(Block *block,Key *key, unsigned long int block_number){
    printf("ECB mode Encryption ...\n");
    for(unsigned long int i=0;i<block_number;i++){
        (block+i)->state = Encryption((block+i)->state, key->exp_key, key->round);
    }
    return block;
}

Block *ECB_Mode_Decryption(Block *block,Key *key, unsigned long int block_number){
    printf("ECB mode Decryption ...\n");
    for(unsigned long int i=0;i<block_number;i++){
        (block+i)->state = Decryption((block+i)->state, key -> exp_key, key -> round);
    }
    return block;
}

Data *InitialData(Data *data,unsigned long int data_size_bytes){
    data -> raw_size_bytes = data_size_bytes;

    // make sure input data size can be divided by 16, if not then padding
    if (data->raw_size_bytes % 16 == 0) {
        data->padding_size_bytes = (data->raw_size_bytes);
    }
    else{
        data->padding_size_bytes = (((data->raw_size_bytes / 16) + 1) * 16) ;
    }

    // initial total buffer = 0
    data->buffer = calloc((data->padding_size_bytes), sizeof(unsigned char));

    return data;
}

Data *ReadFile(char *file_name, Data *data) {
    FILE *file_ptr;
    unsigned long int file_size_bytes;

    file_ptr = fopen(file_name, "rb");            // Open the file in binary mode
    fseek(file_ptr, 0, SEEK_END);                 // Jump to the end of the file
    file_size_bytes = ftell(file_ptr);            // Get the current byte offset in the file
    rewind(file_ptr);                             // Jump back to the beginning of the file

    data = InitialData(data,file_size_bytes);     // Initial struct data value

    fread(data->buffer, file_size_bytes, 1, file_ptr); // Read in the entire file
    fclose(file_ptr); // Close the file

    return data;
}

void WriteFile(char *file_name, Data *data) {
    FILE *file_ptr;

    file_ptr = fopen(file_name, "wb");// Open the file in binary mode
    fwrite(data->buffer, 1, (data->padding_size_bytes), file_ptr); // Read in the entire file

    fclose(file_ptr); // Close the file
}

Block *Data2Blocks(Data *data, Block *block, unsigned long int block_number) {
    for (unsigned long int i = 0; i < block_number; i++) {
        (block + i)->state = malloc(4 * sizeof(unsigned int));
        for (unsigned long int j = 0 + 4 * i; j < 4 + 4 * i; j++) {
            (block + i)->state[j%4] = (unsigned int) data->buffer[0 + 4 * j] << 24 |
                                      (unsigned int) data->buffer[1 + 4 * j] << 16 |
                                      (unsigned int) data->buffer[2 + 4 * j] << 8 |
                                      (unsigned int) data->buffer[3 + 4 * j];
        }
    }
    return block;
}

Data *Blocks2Data(Data *data, Block *block, unsigned long int block_number) {
    unsigned long int x = 0;
    for (unsigned long int i = 0; i < block_number; i++) {
        for ( int j = 0; j < 4; j++) {
            for(int k = 3; k > -1; k--){
                data->buffer[x] = (unsigned char)((((block + i)->state[j]) >> (8*k)) & 0xff);
                x++;
            }

        }
    }
    return data;
}

Key *InitialKey(unsigned char *inp_key, Key *key,int key_size_bits) {
    key->key_size_bits = key_size_bits;
    key->number_keys = key->key_size_bits / 32; // 128=>4 keys, 192=>6 keys, 256=>8 keys
    key->round = key->number_keys + 6;          // 128=>10 round, 192=>12 round, 256=>14 round
    printf("number keys: %d\n", key->number_keys);
    printf("round: %d\n", key->round);

    key->exp_key = (unsigned int *) malloc(sizeof(unsigned int) * (4 * (key->round + 1)));
    key->exp_key = KeyExpansion(inp_key, key->exp_key, key->number_keys, key->round);
    return key;
}

void PrintBlock(Block *block, unsigned long int block_number){
    for(unsigned long int i=0;i<block_number;i++){
        printf("\nblock: %lu\n",i);
        PrintState((block+i)->state);
    }
}




