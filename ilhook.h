#pragma once

#include <windows.h>

#define MAX_PATCH_LENGTH 0x20

enum PatchType
{
    PT_Win32API,
    PT_Call,
    PT_Any,
};

class CodePattern
{
public:
    BYTE* pattern;
    BYTE* mask;
    DWORD length;
};

//use class only to extend struct
class CodePatternFix:public CodePattern
{
public:
	BYTE _pat[MAX_PATCH_LENGTH];
	BYTE _mask[MAX_PATCH_LENGTH];
};

struct HookSrcObject
{
    void* addr;
    PatchType type;
    CodePatternFix pattern;
};



bool InitializeHookSrcObject(HookSrcObject* obj,BYTE* addr);
bool InitializePattern(CodePattern* pattern,BYTE* code,BYTE* mask,DWORD len);

bool IsPatternMatch(BYTE* buff,CodePattern* pat);

bool Hook(HookSrcObject* obj,CodePattern* pre,void* newFunc,char* funcArgs);

//in asmhelper.cpp

bool GetOpInfo(BYTE* addr,int* opLength,bool* isJmpOrCall);
bool GeneratePushInsts(char* seq,BYTE* addr,int* length);
