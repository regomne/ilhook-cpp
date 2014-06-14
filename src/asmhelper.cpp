
#include <windows.h>

#define BEA_ENGINE_STATIC
//#define BEA_USE_STDCALL
#include <beaengine/BeaEngine.h>
#include "ilhook.h"

/*
static unsigned long MaskTable[518]={
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000000, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000000, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000000, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000000, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000008, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000008, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000008, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000008, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00004000, 0x00004000,
	0x00000008, 0x00000008, 0x00001008, 0x00000018,
	0x00002000, 0x00006000, 0x00000100, 0x00004100, // 
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00004100, 0x00006000, 0x00004100, 0x00004100,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00002002, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000020, 0x00000020, 0x00000020, 0x00000020,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000100, 0x00002000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00002000, 0x00002000, 0x00002000, 0x00002000,
	0x00002000, 0x00002000, 0x00002000, 0x00002000,
	0x00004100, 0x00004100, 0x00000200, 0x00000000,
	0x00004000, 0x00004000, 0x00004100, 0x00006000,
	0x00000300, 0x00000000, 0x00000200, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00000100, 0x00000100, 0x00000000, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00002000, 0x00002000, 0x00002002, 0x00000100,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000008, 0x00000000, 0x00000008, 0x00000008,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0x00002000, 0x00002000, 0x00002000, 0x00002000,
	0x00002000, 0x00002000, 0x00002000, 0x00002000,
	0x00002000, 0x00002000, 0x00002000, 0x00002000,
	0x00002000, 0x00002000, 0x00002000, 0x00002000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00000000, 0x00000000, 0x00000000, 0x00004000,
	0x00004100, 0x00004000, 0xFFFFFFFF, 0xFFFFFFFF,
	0x00000000, 0x00000000, 0x00000000, 0x00004000,
	0x00004100, 0x00004000, 0xFFFFFFFF, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0xFFFFFFFF, 0xFFFFFFFF, 0x00004100, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF
};
*/

int GetOpCodeSize32(void* Start)
{
    DISASM dis;
    memset(&dis, 0, sizeof(dis));
    dis.EIP = (UIntPtr)Start;
    int len = Disasm(&dis);
    if (len > 0)
        return len;
    return -1;
}

/*
int GetOpCodeSize32(void* Start)
{
	DWORD* Tlb=(DWORD*)MaskTable;
	PBYTE pOPCode;
	DWORD t, c;
	BYTE dh, dl, al;
	int OpCodeSize =-1;

	t = 0;
	pOPCode = (PBYTE) Start;
	c = 0;

	do {
		t &= 0x0F7;
		c = *(BYTE *) pOPCode++;
		t |= Tlb[c] ;

	} while( ((t & 0x000000FF) & 8) != 0);

	if ((c == 0x0F6) || (c == 0x0F7))
	{
		t |= 0x00004000;
		if ( (0x38 & *(BYTE *) pOPCode++) == 0)
			t |= 0x00008000;
	}
	else if (c == 0x0CD)
	{
		t |= 0x00000100;
		if ( (*(BYTE *) pOPCode++) == 0x20)
			t |= 0x00000400;
	}
	else if (c == 0x0F)
	{
		al = *(BYTE *) pOPCode++;
		t |= Tlb[al + 0x100];
		if (t == 0xFFFFFFFF)
			return OpCodeSize;
	}

	if ((((t & 0x0000FF00) >> 8) & 0x80) != 0)
	{
		dh = (t & 0x0000FF00) >> 8;
		dh ^= 0x20;
		if ((c & 1) == 0) 
			dh ^= 0x21;
		t &= 0xFFFF00FF;
		t |= (dh << 8);
	}

	if ((((t & 0x0000FF00) >> 8) & 0x40) != 0 ) 
	{
		al = *(BYTE *) pOPCode++;
		c = (DWORD)al;
		c |= (al << 8);
		c &= 0xC007;
		if ( (c & 0x0000FF00) != 0xC000 )
		{
			if ( ((t & 0x000000FF) & 0x10) == 0)
			{
				if ((c & 0x000000FF) == 4)
				{
					al = *(BYTE *) pOPCode++;
					al &= 7;
					c &= 0x0000FF00;
					c |= al;
				}

				if ((c & 0x0000FF00) != 0x4000)
				{
					if ((c & 0x0000FF00) == 0x8000)    t |= 4;
					else if (c==5) t |= 4;
				}
				else
					t |= 1;

			}
			else
			{
				if (c != 6)
				{
					if((c & 0x0000FF00) == 0x4000)
						t |= 1;
					else if ((c & 0x0000FF00) == 0x8000) 
						t |= 2;
				}
				else
					t |= 2;
			}
		}
	}

	if ((((t & 0x000000FF)) & 0x20) != 0)
	{
		dl = t & 0x000000FF;
		dl ^= 2;
		t &= 0xFFFFFF00;
		t |= dl;
		if ((dl & 0x10) == 0)
		{
			dl ^= 6;
			t &= 0xFFFFFF00;
			t |= dl;
		}
	}

	if ((((t & 0x0000FF00) >> 8) & 0x20) != 0)
	{
		dh = (t & 0x0000FF00) >> 8;
		dh ^= 2;   
		t &= 0xFFFF00FF;
		t |= (dh << 8);
		if ((dh & 0x10) == 0)
		{
			if (dh & 0x40) //是否是 0x6x
				dh ^= 1;   // 当dh = 0x2x 这里计算多2，当＝62的时候却是 异或1
			t &= 0xFFFFFF00;
			t |= dh;
		}
	}

	OpCodeSize = (DWORD) pOPCode - (DWORD) Start;
	t &= 0x707;
	OpCodeSize += t & 0x000000FF;
	OpCodeSize += (t & 0x0000FF00) >> 8;
	if (((*(char*)Start) & 0x000000FF) == 0x66)    
		if ( OpCodeSize >= 6)   
			OpCodeSize -= 2;   //减2处理 ，将 dword 型转成 word 型

	return OpCodeSize;
}

bool GetOpInfo(BYTE* addr,int* opLength,void** relativeDestAddr)
{
	*opLength=GetOpCodeSize32(addr);
	BYTE* p=addr;
	bool isJmp=false;
	int dist=0;
	if(*p==0xe9 || *p==0xe8)
	{
		isJmp=true;
		dist=*(int*)(p+1);
		p+=5;
	}
	else if(*p==0xf && ((p[1] & 0xf0) == 0x80))
	{
		isJmp=true;
		dist=*(int*)(p+2);
		p+=6;
	}
	else if(*p==0xeb || ((*p & 0xf0)==0x70))
	{
		isJmp=true;
		dist=*(char*)(p+1);
		p+=2;
	}
	if(isJmp)
		*relativeDestAddr=p+dist;

	return true;
}
*/

bool GeneratePushInsts(char* seq,BYTE* addr,int* length,DWORD** oriFuncAddr, DWORD srcAddr)
{
	BYTE* p=addr;
	BYTE* pend=p+*length;

#define TEST_BUFF(cnt) if(p+(cnt)>pend) {SetLastError(ERROR_INSUFFICIENT_BUFFER);return false;}

	TEST_BUFF(2);
	*(WORD*)p=0xec8b; //mov ebp,esp
	p+=2;

	char* ps=seq+strlen(seq)-1;

	while(ps>=seq)
	{
		char ctrl=*ps--;
		if(ctrl>=1 && ctrl<=0x16)
		{
			TEST_BUFF(4);
			//lea eax,[ebp+XX]
			//push eax
			*(WORD*)p=0x458d;
			*(p+2)=0x24+(ctrl-1)*4;
			*(p+3)=0x50;
			p+=4;
		}
		else if((ctrl>='1' && ctrl<='9') || (ctrl>='A' && ctrl<='M'))
		{
			if(ctrl<='9')
				ctrl-='1';
			else
				ctrl-='A'-9;

			TEST_BUFF(3);
			//push [ebp+XX]
			*(WORD*)p=0x75ff;
			*(p+2)=0x24+ctrl*4;
			p+=3;
		}
		else
		{
			TEST_BUFF(5);
			switch(ctrl)
			{
			case 'a':
				*(WORD*)p=0x75ff; //push [ebp+1c]
				*(p+2)=0x1c;
				p+=3;
				break;
			case 'b':
				*p++=0x53;
				break;
			case 'c':
				*p++=0x51;
				break;
			case 'd':
				*p++=0x52;
				break;
			case 'w':
				*(WORD*)p=0x75ff; //push [ebp+0c]
				*(p+2)=0xc;
				p+=3;
				break;
			case 'x':
				*(WORD*)p=0x75ff; //push [ebp+8]
				*(p+2)=0x8;
				p+=3;
				break;
			case 'y':
				*p++=0x56;
				break;
			case 'z':
				*p++=0x57;
				break;
			case 'f':
				if(!oriFuncAddr)
				{
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				*p++=0x68; //push XXXXXXXX
				*oriFuncAddr=(DWORD*)p;
				p+=4;
				break;
			case 'r':
				*p++=0x55; //push ebp
				break;
            case 's':
                *p++ = 0x68;
                *(DWORD*)p = srcAddr;
                p += 4;
                break;
			}
		}
	}
	*length=p-addr;
	return true;
}