#!/bin/bash

sed -i s/"^#define EXECUTE_CRC"/"\/\/#define EXECUTE_CRC"/g  main.c
sed -i s/"^#define EXECUTE_HASH_LOOKUP"/"\/\/#define EXECUTE_HASH_LOOKUP"/g  main.c
sed -i s/"^#define EXECUTE_CLASSIFICATION"/"\/\/#define EXECUTE_CLASSIFICATION"/g  main.c
sed -i s/"^#define EXECUTE_DPI"/"\/\/#define EXECUTE_DPI"/g  main.c

if [ "$1" == "crc" ]; then
    sed -i s/"^\/\/#define EXECUTE_CRC"/"#define EXECUTE_CRC"/g main.c
elif [ "$1" == "hash" ]; then
    sed -i s/"^\/\/#define EXECUTE_HASH_LOOKUP"/"#define EXECUTE_HASH_LOOKUP"/g main.c
elif [ "$1" == "pc" ]; then
    sed -i s/"^\/\/#define EXECUTE_CLASSIFICATION"/"#define EXECUTE_CLASSIFICATION"/g main.c
elif [ "$1" == "dpi" ]; then
    sed -i s/"^\/\/#define EXECUTE_DPI"/"#define EXECUTE_DPI"/g main.c
elif [ "$1" == "raw" ]; then
    echo "" > /dev/null   
else
    echo "please identify app type: crc, hash, pc, dpi, raw"
    exit -1
fi
echo "mode: $1"

if [ "$2" != "" ]; then
    sed -i s/"^#define NB_BUF [0-9]*"/"#define NB_BUF $2"/g main.c
else
    echo "please identify pool size: <number>"
    exit -1
fi

make clean; make
