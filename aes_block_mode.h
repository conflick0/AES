

#ifndef AES_AES_BLOCK_MODE_H
#define AES_AES_BLOCK_MODE_H

typedef struct {
    unsigned long int raw_size_bytes;     // Origin data size (bytes)
    unsigned long int padding_size_bytes; // After padding data size (bytes)
    unsigned char *buffer;                // Store data
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

Block *ECB_Mode_Encryption(Block *block,Key *key, unsigned long int block_number);

Block *ECB_Mode_Decryption(Block *block,Key *key, unsigned long int block_number);

Data *InitialData(Data *data,unsigned long int data_size_bytes);

Data *ReadFile(char *file_name, Data *data);

void WriteFile(char *file_name, Data *data);

Block *Data2Blocks(Data *data, Block *block, unsigned long int block_number);

Data *Blocks2Data(Data *data, Block *block, unsigned long int block_number);

Key *InitialKey(unsigned char *inp_key, Key *key,int key_size_bits) ;

#endif //AES_AES_BLOCK_MODE_H
