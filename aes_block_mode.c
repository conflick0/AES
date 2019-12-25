

#include<stdio.h>
#include<stdlib.h>
#include "aes_block_mode.h"
#include "aes.h"
unsigned int *XOR(unsigned int *inp1_state, unsigned int *inp2_state) {
    unsigned int *state;
    state = malloc(sizeof(unsigned int) * 4);

    for (int i = 0; i < 4; i++) {
        state[i] = inp1_state[i] ^ inp2_state[i];
    }

    return state;
}

unsigned int *CopyState(unsigned int *out_state, unsigned int *inp_state) {
    for (int i = 0; i < 4; i++) {
        out_state[i] = inp_state[i];
    }
    return out_state;
}

Block *InitialIV(Block *IV) {
    unsigned char test_iv_value[16] = "1234567812345678";//just for test
    Data *raw_IV;
    raw_IV = malloc(sizeof(Data));
    raw_IV->raw_size_bytes = 16;
    raw_IV->padding_size_bytes = 16;
    raw_IV->buffer = test_iv_value;

    IV = Data2Blocks(raw_IV, IV, 1);
    return IV;
}

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

Block *CBC_Mode_Encryption(Block *block, Key *key, unsigned long int block_number) {
    printf("CBC mode Encryption ...\n");
    Block *IV;

    IV = malloc(sizeof(Block));
    IV = InitialIV(IV);

    (block + 0)->state = XOR((block + 0)->state, IV->state);
    (block + 0)->state = Encryption((block + 0)->state, key->exp_key, key->round);

    for (unsigned long int i = 1; i < block_number; i++) {
        (block + i)->state = XOR((block + i)->state, (block + i - 1)->state);
        (block + i)->state = Encryption((block + i)->state, key->exp_key, key->round);
    }

    return block;
}


Block *CBC_Mode_Decryption(Block *block, Key *key, unsigned long int block_number) {
    printf("CBC mode Decryption ...\n");
    Block *IV, *prev;

    IV = malloc(sizeof(Block));
    IV = InitialIV(IV);

    prev = malloc(sizeof(Block));
    prev->state = malloc(sizeof(unsigned int) * 4);

    for (unsigned long int i = 0; i < block_number; i++) {
        prev->state = CopyState(prev->state, (block + i)->state);
        (block + i)->state = Decryption((block + i)->state, key->exp_key, key->round);
        (block + i)->state = XOR((block + i)->state, IV->state);
        IV->state = CopyState(IV->state, prev->state);
    }

    return block;
}

Block *PCBC_Mode_Encryption(Block *block, Key *key, unsigned long int block_number) {
    printf("PCBC mode Encryption ...\n");
    Block *IV, *prev;

    IV = malloc(sizeof(Block));
    IV = InitialIV(IV);

    prev = malloc(sizeof(Block));
    prev->state = malloc(sizeof(unsigned int) * 4);


    prev->state = CopyState(prev->state, (block + 0)->state);
    (block + 0)->state = XOR((block + 0)->state, IV->state);
    (block + 0)->state = Encryption((block + 0)->state, key->exp_key, key->round);

    for (unsigned long int i = 1; i < block_number; i++) {
        IV->state = XOR((block + i - 1)->state, prev->state);
        prev->state = CopyState(prev->state, (block + i)->state);
        (block + i)->state = XOR((block + i)->state, IV->state);
        (block + i)->state = Encryption((block + i)->state, key->exp_key, key->round);
    }

    return block;
}


Block *PCBC_Mode_Decryption(Block *block, Key *key, unsigned long int block_number) {
    printf("PCBC mode Decryption ...\n");
    Block *IV, *prev;

    IV = malloc(sizeof(Block));
    IV = InitialIV(IV);

    prev = malloc(sizeof(Block));
    prev->state = malloc(sizeof(unsigned int) * 4);

    prev->state = CopyState(prev->state, (block + 0)->state);
    (block + 0)->state = Decryption((block + 0)->state, key->exp_key, key->round);
    (block + 0)->state = XOR((block + 0)->state, IV->state);

    for (unsigned long int i = 1; i < block_number; i++) {
        IV->state = XOR((block + i - 1)->state, prev->state);
        prev->state = CopyState(prev->state, (block + i)->state);
        (block + i)->state = Decryption((block + i)->state, key->exp_key, key->round);
        (block + i)->state = XOR((block + i)->state, IV->state);
    }

    return block;
}


Data *ShiftIV_8_bit(Data *raw_IV, unsigned char buffer) {
    for (int i = 0; i < 15; i++) {
        raw_IV->buffer[i] = raw_IV->buffer[i + 1];
    }
    raw_IV->buffer[15] = buffer;
    return raw_IV;
}

Data *CFB_8_Mode_Encryption(Data *data, Key *key) {
    printf("CFB-8 mode Encryption ...\n");
    Block *IV;
    Data *raw_IV;

    IV = malloc(sizeof(Block));
    IV = InitialIV(IV);

    raw_IV = malloc(sizeof(Data));
    raw_IV->raw_size_bytes = 16;
    raw_IV->padding_size_bytes = 16;
    raw_IV->buffer = calloc(sizeof(unsigned char), 16);
    raw_IV = Blocks2Data(raw_IV, IV, 1);

    for (unsigned long int i = 0; i < data->padding_size_bytes; i++) {
        IV = Data2Blocks(raw_IV, IV, 1);
        Encryption(IV->state, key->exp_key, key->round);
        raw_IV = Blocks2Data(raw_IV, IV, 1);
        data->buffer[i] = (data->buffer[i]) ^ raw_IV->buffer[0];
        raw_IV = ShiftIV_8_bit(raw_IV, data->buffer[i]);

    }

    return data;
}

Data *CFB_8_Mode_Decryption(Data *data, Key *key) {
    printf("CFB-8 mode Decryption ...\n");
    Block *IV;
    unsigned char prev_buffer;
    Data *raw_IV;

    IV = malloc(sizeof(Block));
    IV = InitialIV(IV);

    raw_IV = malloc(sizeof(Data));
    raw_IV->raw_size_bytes = 16;
    raw_IV->padding_size_bytes = 16;
    raw_IV->buffer = calloc(sizeof(unsigned char), 16);
    raw_IV = Blocks2Data(raw_IV, IV, 1);

    for (unsigned long int i = 0; i < data->padding_size_bytes; i++) {
        prev_buffer = data->buffer[i];
        IV = Data2Blocks(raw_IV, IV, 1);
        Encryption(IV->state, key->exp_key, key->round);
        raw_IV = Blocks2Data(raw_IV, IV, 1);
        data->buffer[i] = (data->buffer[i]) ^ raw_IV->buffer[0];
        raw_IV = ShiftIV_8_bit(raw_IV, prev_buffer);
    }

    return data;
}

Data *ShiftIV_1_bit(Data *raw_IV, unsigned char padding_buffer) {

    for (int i = 0; i < 15; i++) {
        // shift left 7 bit and padding 1 bit
        raw_IV->buffer[i] = ((raw_IV->buffer[i] << 1) |
                             (raw_IV->buffer[i + 1] >> 7) & 0x01);
    }
    // last byte shift left 7 bit and padding 1 bit
    raw_IV->buffer[15] = ((raw_IV->buffer[15] << 1) | padding_buffer);

    return raw_IV;
}

Data *CFB_1_Mode_Encryption(Data *data, Key *key) {
    printf("CFB-1 mode Encryption ...\n");
    Block *IV;
    Data *raw_IV;
    unsigned char out_byte;
    unsigned char inp_byte;

    IV = malloc(sizeof(Block));
    IV = InitialIV(IV);

    raw_IV = malloc(sizeof(Data));
    raw_IV->raw_size_bytes = 16;
    raw_IV->padding_size_bytes = 16;
    raw_IV->buffer = calloc(sizeof(unsigned char), 16);
    raw_IV = Blocks2Data(raw_IV, IV, 1);

    for (unsigned long int i = 0; i < data->padding_size_bytes; i++) {
        out_byte = 0;
        // extract one bit and encryption
        for(int left_shift_bit=7;left_shift_bit>-1;left_shift_bit--){
            inp_byte = (data->buffer[i] >> left_shift_bit) & 0x01; // extract one bit
            IV = Data2Blocks(raw_IV, IV, 1);
            Encryption(IV->state, key->exp_key, key->round);
            raw_IV = Blocks2Data(raw_IV, IV, 1);
            inp_byte = inp_byte ^ ((raw_IV->buffer[0] >> 7 ) & 0x01); // one bit xor
            raw_IV = ShiftIV_1_bit(raw_IV, inp_byte);
            out_byte = out_byte | (inp_byte << left_shift_bit); // store one bit to tmp_buffer

        }
        data->buffer[i] = out_byte;
    }

    return data;
}

Data *CFB_1_Mode_Decryption(Data *data, Key *key) {
    printf("CFB-1 mode Decryption ...\n");
    Block *IV;
    Data *raw_IV;
    unsigned char prev_byte;
    unsigned char out_byte;
    unsigned char inp_byte;

    IV = malloc(sizeof(Block));
    IV = InitialIV(IV);

    raw_IV = malloc(sizeof(Data));
    raw_IV->raw_size_bytes = 16;
    raw_IV->padding_size_bytes = 16;
    raw_IV->buffer = calloc(sizeof(unsigned char), 16);
    raw_IV = Blocks2Data(raw_IV, IV, 1);

    for (unsigned long int i = 0; i < data->padding_size_bytes; i++) {
        out_byte = 0;
        // extract one bit and encryption
        for(int left_shift_bit=7;left_shift_bit>-1;left_shift_bit--){
            inp_byte = (data->buffer[i] >> left_shift_bit) & 0x01; // extract one bit
            prev_byte = inp_byte ;
            IV = Data2Blocks(raw_IV, IV, 1);
            Encryption(IV->state, key->exp_key, key->round);
            raw_IV = Blocks2Data(raw_IV, IV, 1);
            inp_byte  = prev_byte  ^ ((raw_IV->buffer[0] >> 7 ) & 0x01);;
            raw_IV = ShiftIV_1_bit(raw_IV, prev_byte);
            out_byte = out_byte | (inp_byte  << left_shift_bit); // store one bit to tmp_buffer
        }
        data->buffer[i] = out_byte;
    }
    return data;
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
    fwrite(data->buffer, 1, data->padding_size_bytes, file_ptr);

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




