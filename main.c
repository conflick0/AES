#include<stdio.h>
#include<stdlib.h>
#include "aes_block_mode.h"
#include "aes.h"


Data *ShiftIV(Data *raw_IV, unsigned char buffer, int shift_bits) {
    int preserve_bits = 8 - shift_bits;
    for (int i = 0; i < 15; i++) {
        raw_IV->buffer[i] = ((raw_IV->buffer[i] >> preserve_bits) << preserve_bits) |
                            (raw_IV->buffer[i + shift_bits] >> shift_bits);
    }
    raw_IV->buffer[16] = buffer;
    return raw_IV;
}

Data *CFB_Mode_Encryption(Data *data, Key *key,int shift_bits) {
    printf("CFB-%d mode Encryption ...\n",shift_bits);
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
        Encryption(IV->state, key->exp_key, key->round);
        data->buffer[i] = (data->buffer[i]) ^ raw_IV->buffer[0];
        raw_IV = ShiftIV(raw_IV, data->buffer[i],shift_bits);
    }

    return data;
}

Data *CFB_Mode_Decryption(Data *data, Key *key,int shift_bits) {
    printf("CFB-%d mode Decryption ...\n",shift_bits);
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
        Encryption(IV->state, key->exp_key, key->round);
        data->buffer[i] = (data->buffer[i]) ^ raw_IV->buffer[0];
        raw_IV = ShiftIV(raw_IV, prev_buffer,shift_bits);
    }

    return data;
}


int main(void) {
    // Hyper parameters
    char *inp_file_name, *out_file_name;
    unsigned long int block_number;
    unsigned char *inp_key;
    int key_size_bits;
    Data *inp_data, *out_data;
    Block *block;
    Key *key;

    // Hyper parameters test value
    int en_de_cryption_flag = 0; // 1 -> encryption, 0 -> decryption
    char test_inp_file_name[100] = "e.txt"; //0.png//e.png//d.png
    char test_out_file_name[100] = "d.txt";
    int special_mode = 1; // 0 -> ECB,CBC,PCBC,CTR, 1 -> CFB,OFB



    unsigned char test_inp_key[16] = "0000000000000000";
    int test_key_size_bits = 128;


    // input file name
    inp_file_name = malloc(sizeof(char) * 100);         // malloc input file name
    out_file_name = malloc(sizeof(char) * 100);         // malloc output file name
    inp_file_name = test_inp_file_name;               // input input file name
    out_file_name = test_out_file_name;               // input output file name


    // initial key
    key = malloc(sizeof(Key));
    key_size_bits = test_key_size_bits;                               // input key size 128/192/256
    inp_key = malloc(sizeof(unsigned char) * ((key->key_size_bits) / 8)); // malloc input key
    inp_key = test_inp_key;                                           // input key
    key = InitialKey(inp_key, key, key_size_bits);                      // initial struct key value and expansion key
    //PrintExpansionKey(key->exp_key);                                // see expansion key result for debug


    // read data(bytes by bytes) from file
    printf("Read file ...\n");
    inp_data = malloc(sizeof(Data));                     // malloc struct inp_data
    inp_data = ReadFile(inp_file_name, inp_data);       // initial struct inp_data value,and read data to inp_data

    // transform data to block
    block_number = (inp_data->padding_size_bytes) / 16;  // compute how many block composed by inp_data
    block = malloc(block_number * sizeof(Block));        // malloc block array
    block = Data2Blocks(inp_data, block, block_number);  // transform inp_data to block



    // block encryption/decryption
    if (en_de_cryption_flag == 1) {
        if (special_mode == 1) {
//            inp_data = CFB_Mode_Encryption(inp_data, key,8);
            inp_data = CFB_Mode_Encryption(inp_data, key,1);
        }
        else {
//            block = ECB_Mode_Encryption(block, key, block_number);
//            block = CBC_Mode_Encryption(block, key, block_number);
//            block = PCBC_Mode_Encryption(block, key, block_number);
//            PrintBlock(block, block_number);
        }


    }
    else {
        if (special_mode == 1) {
//            inp_data = CFB_Mode_Decryption(inp_data, key,8);
            inp_data = CFB_Mode_Decryption(inp_data, key,1);
        }
        else {
//            block = ECB_Mode_Decryption(block, key, block_number);
//            block = CBC_Mode_Decryption(block, key, block_number);
//            block = PCBC_Mode_Decryption(block, key, block_number);
//            PrintBlock(block, block_number);
        }
    }

    if (special_mode == 1) {
        out_data = malloc(sizeof(Data));// malloc out_data
        out_data = inp_data;
    }
    else {
        //transform block to data
        out_data = malloc(sizeof(Data));                            // malloc out_data
        out_data = InitialData(out_data, inp_data->padding_size_bytes);  // initial struct out_data value
        out_data = Blocks2Data(out_data, block, block_number);        // transform block to out_data

    }

    // write encryption data to file
    printf("\nOutput file ...\n");
    WriteFile(out_file_name, out_data);


    return 0;
}



