#pragma once

#include <windows.h>

#define MAX_PATCH_LENGTH 0x20

enum PatchType
{
    PT_Win32API,
    PT_Call,
    PT_Any,
};

struct CodePattern
{
    BYTE pattern[MAX_PATCH_LENGTH];
    BYTE mask[MAX_PATCH_LENGTH];
    DWORD length;
};

struct HookObject
{
    void* addr;
    PatchType type;
    CodePattern pattern;
};

typedef struct CodePattern* PCodePattern;
typedef struct HookObject* PHookObject;

bool InitializeHookObjectFromAddr(PHookObject obj,BYTE* addr,int minLength);
bool InitializePattern(PCodePattern pattern,BYTE* code,BYTE* mask,DWORD len);

bool IsPatternMatch(PCodePattern pat1,PCodePattern pat2);

bool Hook(PHookObject obj,PCodePattern pre,void* newFunc,char* funcArgs);

//in asmhelper.cpp

bool GetOpInfo(BYTE* addr,int* opLength,bool* isJmpOrCall);
bool GeneratePushInsts(char* seq,BYTE* addr,int* length);
