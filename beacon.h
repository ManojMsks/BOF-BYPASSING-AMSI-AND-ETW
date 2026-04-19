#pragma once
#include <windows.h>

typedef struct {
    char * original; // The raw pointer to the start of the data
    char * buffer;   // A moving pointer used to "read" through the data
    int    length;   // How much data is left to read
    int    size;     // The total size of the original data
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT void    BeaconPrintf(int type, char * fmt, ...);

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_ERROR       0x0d
