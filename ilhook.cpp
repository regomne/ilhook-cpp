
#include <windows.h>
#include "ilhook.h"

bool GenerateStub(HookSrcObject* srcObj,HookStubObject* stubObj,void* newFunc,char* funcArgs)
{
	BYTE* oriFunc;
	DWORD* newOriFuncPtr=0;

	BYTE* pst=(BYTE*)stubObj->addr;
	BYTE* pstend=pst+stubObj->length;

	if(!CalcOriAddress(srcObj,(void**)&oriFunc))
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}

#define TEST_BUFF(cnt) if(pst+(cnt)>pstend) {SetLastError(ERROR_INSUFFICIENT_BUFFER);return false;}

	TEST_BUFF(6);
	*pst++=0x60; //pushad

	if(funcArgs)
	{
		int length=pstend-pst;
		if(!GeneratePushInsts(funcArgs,pst,&length,&newOriFuncPtr))
			return false;
		pst+=length;
	}

	//call xxxxxxxx
	*pst=0xe8;
	*(DWORD*)(pst+1)=(BYTE*)newFunc-(pst+5);
	pst+=5;

	if(stubObj->options & STUB_NEEDRETURNVALUE)
	{
		TEST_BUFF(4);
		*(DWORD*)pst=0x1c244489; //mov [esp+1ch],eax
		pst+=4;
	}
	TEST_BUFF(1);
	*pst++=0x61; //popad

	if(stubObj->options & STUB_USERETN)
	{
		TEST_BUFF(3);
		if(stubObj->retnVal==0)
			*pst++=0xc3; //ret
		else
		{
			*pst=0xc2; //retn XX
			*(WORD*)(pst+1)=stubObj->retnVal;
			pst+=3;
		}
	}
	if(!(stubObj->options & STUB_USERETN) || newOriFuncPtr)
	{
		if(newOriFuncPtr)
			*newOriFuncPtr=(DWORD)pst;

		//write the stolen code
		if(srcObj->type==PT_ANY)
		{
			TEST_BUFF(srcObj->pattern.length);
			memcpy(pst,srcObj->pattern.pattern,srcObj->pattern.length);

			//relocate jmp or call op
			if(srcObj->relocPosition!=-1)
			{
				*(DWORD*)(pst+srcObj->relocPosition)=
					(BYTE*)srcObj->relocDestAddr-(pst+srcObj->relocPosition+4);
			}
			pst+=srcObj->pattern.length;
		}

		TEST_BUFF(5);
		*pst=0xe9; //jmp oriAddr
		*(DWORD*)(pst+1)=oriFunc-(pst+5);
		pst+=5;
	}
}

bool Hook32(HookSrcObject* srcObj,CodePattern* pre,HookStubObject* stubObj,void* newFunc,char* funcArgs)
{
	if(pre && !IsPatternMatch(srcObj->addr,pre))
		return false;

	if(!GenerateStub(srcObj,stubObj,newFunc,funcArgs))
		return false;

	if(!PatchHookSrc(srcObj,stubObj->addr))
		return false;

	return true;
}