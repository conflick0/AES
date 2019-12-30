# AES
Information security homework, implement AES-128, AES-192 and AES-256 encryption/decryption.Furthermore, implement Block cipher mode of operation ECB, CBC, PCBC, CFB, OFB and CTR.

## Installation
### Requirements
- gcc
- Windows or Linux
### Installing gcc on Windows or Linux
#### On Windows
- Reference [here](https://sites.google.com/site/mycprogrammingbook/bu-chong-cai-liao/gccanzhuang)

#### On Linux
```
sudo apt install build-essential
```

## Usage
### On Windows
#### Compile
```
gcc main.c aes.c aes_const.c aes_block_mode.c -o main.exe
```
#### Execution
- click ***main.exe***

### On Linux
#### Compile
```
gcc main.c aes.c aes_const.c aes_block_mode.c -o main.out
```
#### Execution
```
./main.out
```

## Note
If your IDE is **Clion**, you need to set your **Working directory**. Otherwise, program could not read the input file.

1. click ***Run -> Edit Configurations***
> ![](https://i.imgur.com/WXlydmu.png)
    
2.  set ***Working directory***

> ![](https://i.imgur.com/OZToRbw.png)
