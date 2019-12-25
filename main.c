#include<stdio.h>
#include<stdlib.h>
#include "aes_block_mode.h"

#define ECB_MODE 0
#define CBC_MODE 1
#define PCBC_MODE 2
#define CFB_8_MODE 3
#define CFB_1_MODE 4
#define OFB_8_MODE 5
#define OFB_1_MODE 6
#define CTR_MODE 7

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
    int en_de_cryption_flag = 0;   // 1 -> encryption, 0 -> decryption
    char test_origin_file_name[100] = "0.png";
    char test_encryption_file_name[100] = "e.png";
    char test_decryption_file_name[100] = "d.png";
    int Block_Mode = PCBC_MODE;  // block operation mode
    int OperationDataType = 1;    // 1 ->block type ECB,CBC,PCBC  0->stream CFB,OFB


    unsigned char test_inp_key[16] = "0000000000000000";
    int test_key_size_bits = 128;


    // input file name
    if(en_de_cryption_flag==1){
        inp_file_name = malloc(sizeof(char) * 100);    // malloc input file name
        out_file_name = malloc(sizeof(char) * 100);    // malloc output file name
        inp_file_name =test_origin_file_name;          // input input file name
        out_file_name = test_encryption_file_name;     // input output file name
    }
    else{
        inp_file_name = malloc(sizeof(char) * 100);    // malloc input file name
        out_file_name = malloc(sizeof(char) * 100);    // malloc output file name
        inp_file_name = test_encryption_file_name;     // input input file name
        out_file_name = test_decryption_file_name;     // input output file name
    }



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

    if (OperationDataType == 1) {
        // transform data to block
        block_number = (inp_data->padding_size_bytes) / 16;  // compute how many block composed by inp_data
        block = malloc(block_number * sizeof(Block));        // malloc block array
        block = Data2Blocks(inp_data, block, block_number);  // transform inp_data to block
    }
    else{
        out_data = malloc(sizeof(Data));// malloc out_data
    }


    // block encryption/decryption
    if (en_de_cryption_flag == 1) {
        switch (Block_Mode){
            case ECB_MODE:
                block = ECB_Mode_Encryption(block, key, block_number);
                break;
            case CBC_MODE:
                block = CBC_Mode_Encryption(block, key, block_number);
                break;
            case PCBC_MODE:
                block = PCBC_Mode_Encryption(block, key, block_number);
                break;
            case CFB_8_MODE:
                out_data = CFB_8_Mode_Encryption(inp_data, key);
                break;
            case CFB_1_MODE:
                out_data = CFB_1_Mode_Encryption(inp_data, key);
                break;
            case OFB_8_MODE:
                break;
            case OFB_1_MODE:
                break;
            case CTR_MODE:
                break;
        }
    }
    else {
        switch (Block_Mode){
            case ECB_MODE:
                block = ECB_Mode_Decryption(block, key, block_number);
                break;
            case CBC_MODE:
                block = CBC_Mode_Decryption(block, key, block_number);
                break;
            case PCBC_MODE:
                block = PCBC_Mode_Decryption(block, key, block_number);
                break;
            case CFB_8_MODE:
                out_data = CFB_8_Mode_Decryption(inp_data, key);
                break;
            case CFB_1_MODE:
                out_data = CFB_1_Mode_Decryption(inp_data, key);
                break;
            case OFB_8_MODE:
                break;
            case OFB_1_MODE:
                break;
            case CTR_MODE:
                break;
        }
    }

    if (OperationDataType== 1) {
        //transform block to data
        out_data = malloc(sizeof(Data));                            // malloc out_data
        out_data = InitialData(out_data, inp_data->padding_size_bytes);  // initial struct out_data value
        out_data = Blocks2Data(out_data, block, block_number);        // transform block to out_data
    }

    // write encryption data to file
    printf("Output file ...\n");
    WriteFile(out_file_name, out_data);


    return 0;
}



