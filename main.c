#include<stdio.h>
#include<stdlib.h>
#include "aes.h"

typedef struct {
    unsigned int raw_size_bytes;     // Origin data size (bytes)
    unsigned int padding_size_bytes; // After padding data size (bytes)
    unsigned char *buffer;           // Store data
} Data;

typedef struct {
    unsigned int *state;
} Block;

typedef struct {
    int key_size_bits;
    int number_keys;             // 128=>4 keys, 192=>6 keys, 256=>8 keys
    int round;                   // 128=>10 round, 192=>12 round, 256=>14 round
    unsigned int *exp_key;
} Key;

Data *ReadFile(char *file_name, Data *data) {
    FILE *file_ptr;

    file_ptr = fopen(file_name, "rb");            // Open the file in binary mode
    fseek(file_ptr, 0, SEEK_END);                 // Jump to the end of the file
    data->raw_size_bytes = ftell(file_ptr);   // Get the current byte offset in the file
    rewind(file_ptr);                             // Jump back to the beginning of the file


    // make sure input data size can be divided by 16, if not then padding.
    if (data->raw_size_bytes % 16 == 0) {
        data->padding_size_bytes = data->raw_size_bytes;
    }
    else{
        data->padding_size_bytes = ((data->raw_size_bytes / 16) + 1) * 16 ;
    }

    data->buffer = calloc((data->padding_size_bytes), sizeof(unsigned char));
    fread(data->buffer, (data->padding_size_bytes), 1, file_ptr); // Read in the entire file
    fclose(file_ptr); // Close the file

    return data;
}

Block *Data2Blocks(Data *data, Block *block, unsigned int block_number) {
    for (unsigned int i = 0; i < block_number; i++) {
        (block + i)->state = malloc(4 * sizeof(unsigned int));
        for (unsigned int j = 0 + 4 * i; j < 4 + 4 * i; j++) {
            (block + i)->state[j%4] = (unsigned int) data->buffer[0 + 4 * j] << 24 |
                                      (unsigned int) data->buffer[1 + 4 * j] << 16 |
                                      (unsigned int) data->buffer[2 + 4 * j] << 8 |
                                      (unsigned int) data->buffer[3 + 4 * j];
        }
    }
    return block;
}

Key *InitialKeys(unsigned char *inp_key, Key *key) {
    key->number_keys = key->key_size_bits / 32; // 128=>4 keys, 192=>6 keys, 256=>8 keys
    key->round = key->number_keys + 6;          // 128=>10 round, 192=>12 round, 256=>14 round
    printf("%d\n",key->number_keys);
    printf("%d\n",key->round);

    key->exp_key = (unsigned int *) malloc(sizeof(unsigned int) * (4 * (key->round + 1)));
    key->exp_key = KeyExpansion(inp_key, key->exp_key, key->number_keys, key->round);
    PrintExpansionKey(key->exp_key);
    return key;
}

Data *Blocks2Data(Data *data, Block *block, unsigned int block_number) {
    int x = 0;
    for (unsigned int i = 0; i < block_number; i++) {
        for (unsigned int j = 0; j < 4; j++) {
            for(int k = 3; k > -1; k--){
                data->buffer[x] = (unsigned char)((((block + i)->state[j]) >> (8*k)) & 0xff);
                x++;
            }

        }
    }
    return data;
}

void WriteFile(char *file_name, Data *data) {
    FILE *file_ptr;

    file_ptr = fopen(file_name, "wb");// Open the file in binary mode

    fwrite(data->buffer, 1, (data->raw_size_bytes), file_ptr); // Read in the entire file
    fclose(file_ptr); // Close the file
}



int main(void) {
    char *inp_file_name,*encryption_file_name,*decryption_file_name;
    unsigned char *inp_key;
    unsigned int block_number;
    Data *inp_data,*out_data;
    Block *block;
    Key *key;


    // input file name
    inp_file_name = malloc(sizeof(char)*100);
    inp_file_name ="0.txt";

    // read data(bytes by bytes) from file
    inp_data=malloc(sizeof(Data));
    inp_data = ReadFile(inp_file_name,inp_data);
    printf("%d\n", inp_data->raw_size_bytes);
    printf("%d\n", inp_data->padding_size_bytes);

    // initial block
    block_number = (inp_data->padding_size_bytes)/16;
    block = malloc(block_number*sizeof(Block));
    block = Data2Blocks(inp_data,block,block_number);



    // input key size
    key = malloc(sizeof(Key));
    key -> key_size_bits = 128;

    // input key
    unsigned char tmp[16] = "0000000000000000";
    inp_key = malloc(sizeof(unsigned char)*((key->key_size_bits)/8));
    inp_key = tmp;

    // initial key
    key = InitialKeys(inp_key,key);
    PrintExpansionKey(key->exp_key);



    printf("Initial blocks:\n");
    for(int i=0;i<(int)block_number;i++){
        PrintState((block+i)->state);
        printf("\n");
    }



    printf("Encryption blocks:\n");
    for(int i=0;i<(int)block_number;i++){
        (block+i)->state = Encryption((block+i)->state, key->exp_key, key->round);
        PrintState((block+i)->state);
        printf("\n");
    }


    printf("Output encryption file\n\n");
    encryption_file_name = malloc(sizeof(char)*100);
    encryption_file_name = "encryption.txt";
    out_data = inp_data;
    out_data = Blocks2Data(out_data,block,block_number);
    WriteFile(encryption_file_name,out_data);



    printf("Decryption blocks:\n");
    for(int i=0;i<(int)block_number;i++){
        (block+i)->state = Decryption((block+i)->state, key -> exp_key, key -> round);
        PrintState((block+i)->state);
        printf("\n");
    }


    printf("Output decryption file\n\n");
    decryption_file_name = malloc(sizeof(char)*100);
    decryption_file_name = "decryption.txt";
    out_data = inp_data;
    out_data = Blocks2Data(out_data,block,block_number);
    WriteFile(decryption_file_name,out_data);
//
    return 0;
}



