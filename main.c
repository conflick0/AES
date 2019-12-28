#include<stdio.h>
#include<stdlib.h>
#include "aes_block_mode.h"
#include "aes.h"

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
    int en_de_cryption_flag;// = 0;   // 1 -> encryption, 0 -> decryption
    int Block_Mode; //= CTR_MODE;  // block operation mode
    int OperationDataType; //= 1;    // 1 ->block type ECB,CBC,PCBC,CTR  0->stream CFB,OFB
//    char test_origin_file_name[100] = "0.png";
//    char test_encryption_file_name[100] = "e.png";
//    char test_decryption_file_name[100] = "d.png";

    int choose;

    // choose encryption or decryption
    printf("Choose (1)encryption or (0)decryption (Enter 1 or 0):");
    scanf("%d",&en_de_cryption_flag);

    // choose Block Mode
    printf("\nBlock Mode:\n");
    printf("0. ECB_Mode\n");
    printf("1. CBC_Mode\n");
    printf("2. PCBC_Mode\n");
    printf("3. CFB_8_Mode\n");
    printf("4. CFB_1_Mode\n");
    printf("5. OFB_8_Mode\n");
    printf("6. OFB_1_Mode\n");
    printf("7. CTR_Mode\n");
    printf("Enter number to choose Block Mode:");
    scanf("%d",&Block_Mode);


    //OperationDataType 1 ->block type ECB,CBC,PCBC,CTR  0->stream CFB,OFB
    if(Block_Mode>=3 && Block_Mode<=6){
        OperationDataType = 0;
    }
    else{
        OperationDataType = 1;
    }

    // chooose key size
    printf("\nKey size:\n");
    printf("0. 128\n");
    printf("1. 192\n");
    printf("2. 256\n");
    printf("Enter number to choose Key size:");
    scanf("%d",&choose);
    switch(choose){
        case 0:
            key_size_bits = 128;
            break;
        case 1:
            key_size_bits = 192;
            break;
        case 2:
            key_size_bits = 256;
            break;
    }


    // input key
    inp_key = malloc(sizeof(char) * (key_size_bits/8)+1);
    printf("Enter key(%d char):",(key_size_bits/8));
    scanf("%s",inp_key);

    // input file name
    inp_file_name = malloc(sizeof(char)*100);
    printf("Enter input file name:");
    scanf("%s",inp_file_name);

    out_file_name = malloc(sizeof(char) * 100);
    printf("Enter output file name:");
    scanf("%s",out_file_name);


    // initial key
    key = malloc(sizeof(Key));
    key = InitialKey(inp_key, key,key_size_bits);      // initial struct key value and expansion key
//    PrintExpansionKey(key->exp_key);                       // see expansion key result for debug


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
                out_data = OFB_8_Mode_Encryption(inp_data, key);
                break;
            case OFB_1_MODE:
                out_data = OFB_1_Mode_Encryption(inp_data, key);
                break;
            case CTR_MODE:
                CTR_Mode_Encryption(block, key, block_number);
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
                out_data = OFB_8_Mode_Decryption(inp_data, key);
                break;
            case OFB_1_MODE:
                out_data = OFB_1_Mode_Decryption(inp_data, key);
                break;
            case CTR_MODE:
                CTR_Mode_Decryption(block, key, block_number);
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



