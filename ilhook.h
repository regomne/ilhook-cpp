#pragma once

#include <windows.h>

#define MAX_PATCH_LENGTH 0x20


enum PatchType
{
    PT_WIN32API,
    PT_CALL,
    PT_ANY,
};

enum StubOptions
{
	//directly return after newFunc called. if not set, jmp to source function.
	STUB_USERETN=1,

	//set eax after newFunc called.
	STUB_NEEDRETURNVALUE=(1<<1),
};

struct CodePattern
{
public:
    BYTE* pattern;
    BYTE* mask;
    DWORD length;
};

struct HookSrcObject
{
    void* addr;
    PatchType type;
    CodePattern pattern;

	//relocation for stolen code of jmp and call
	int relocPosition;
	void* relocDestAddr;

	//for CodePattern
	BYTE _pat[MAX_PATCH_LENGTH];
	BYTE _msk[MAX_PATCH_LENGTH];
};

struct HookStubObject
{
	void* addr;
	int length;
	StubOptions options;
	int retnVal;
};

bool InitializeHookSrcObject(HookSrcObject* obj,BYTE* addr,int maxPatchLength=-1);
bool InitializePattern(CodePattern* pattern,BYTE* code,BYTE* mask,DWORD len);
bool InitializeStubObject(HookStubObject* obj,void* addr,int length,StubOptions options=(StubOptions)0,int retvVal=0);

bool CalcOriAddress(HookSrcObject* obj, void** addr);
bool IsPatternMatch(void* buff,CodePattern* pat);

bool PatchMemory(void* addr,CodePattern* pre);
bool PatchHookSrc(HookSrcObject* srcObj,void* destAddr);
bool GenerateStub(HookSrcObject* srcObj,HookStubObject* stubObj,void* newFunc,char* funcArgs);

bool Hook32(HookSrcObject* srcObj,CodePattern* pre,HookStubObject* stubObj,void* newFunc,char* funcArgs);

//in asmhelper.cpp

bool GetOpInfo(BYTE* addr,int* opLength,bool* isJmpOrCall);
bool GeneratePushInsts(char* seq,BYTE* addr,int* length,DWORD** oriFuncAddr);
