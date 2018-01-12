cmake_minimum_required(VERSION 3.9)
project (cpuminer-neoscrypt)
file(GLOB C_SOURCES *.c)
file(GLOB S_SOURCES neoscrypt_asm.S sha2-x64.S scrypt-x64.S)

add_definitions(-DCURL_STATICLIB -DASM -DOPT -DMINER_4WAY -DSHA256)

add_executable (minerd ${C_SOURCES} ${S_SOURCES})

# -fno-strict-aliasing