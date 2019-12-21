cmake_minimum_required(VERSION 3.15)
project(AES C)

set(CMAKE_C_STANDARD 99)

add_executable(AES main.c aes.c aes.h aes_block_mode.c aes_block_mode.h aes_const.c aes_const.h)