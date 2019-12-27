

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

unsigned int *XOR(unsigned int *inp1_state, unsigned int *inp2_state);

unsigned int *CopyState(unsigned int *out_state, unsigned int *inp_state);

Block *InitialIV(Block *IV, int en_de_flag);

Block* ECB_Mode_Encryption(Block *block,Key *key, unsigned long int block_number);

Block *ECB_Mode_Decryption(Block *block,Key *key, unsigned long int block_number);

Block *CBC_Mode_Encryption(Block *block, Key *key, unsigned long int block_number);

Block *CBC_Mode_Decryption(Block *block, Key *key, unsigned long int block_number);

Block *PCBC_Mode_Encryption(Block *block, Key *key, unsigned long int block_number);

Block *PCBC_Mode_Decryption(Block *block, Key *key, unsigned long int block_number);

Data *ShiftIV_8_bit(Data *raw_IV, unsigned char last_byte);

Data *CFB_8_Mode_Encryption(Data *data, Key *key);

Data *CFB_8_Mode_Decryption(Data *data, Key *key);

Data *ShiftIV_1_bit(Data *raw_IV, unsigned char last_bit);

Data *CFB_1_Mode_Encryption(Data *data, Key *key);

Data *CFB_1_Mode_Decryption(Data *data, Key *key);

Data *OFB_8_Mode_Encryption(Data *data, Key *key);

Data *OFB_8_Mode_Decryption(Data *data, Key *key);

Data *OFB_1_Mode_Encryption(Data *data, Key *key);

Data *OFB_1_Mode_Decryption(Data *data, Key *key);

Data *InitialData(Data *data,unsigned long int data_size_bytes);

Data *ReadFile(char *file_name, Data *data);

void WriteFile(char *file_name, Data *data);

Block *Data2Blocks(Data *data, Block *block, unsigned long int block_number);

Data *Blocks2Data(Data *data, Block *block, unsigned long int block_number);

Key *InitialKey(unsigned char *inp_key, Key *key,int key_size_bits) ;

void PrintBlock(Block *block, unsigned long int block_number);

#endif //AES_AES_BLOCK_MODE_H
