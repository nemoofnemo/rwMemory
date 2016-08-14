#include <Windows.h>
#include <TlHelp32.h>
#include <list>
#include <utility>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

using std::list;
using std::pair;
using std::iterator;

typedef  DWORD (WINAPI *SUSPENDPROCESS)(HANDLE);
typedef  DWORD (WINAPI *RESUMEPROCESS)(HANDLE);

SUSPENDPROCESS SuspendProcess;
RESUMEPROCESS ResumeProcess;

BOOL isMemEqual( void * data1 , void * data2 , DWORD size ){
	return ( memcmp( data1 , data2 , (size_t)size ) == 0);
}

//根据进程名查找进程句柄
DWORD getPidByName( WCHAR * name , list<DWORD> * pList){
	HANDLE snapshot;
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof( processInfo );
	
	if(( snapshot = CreateToolhelp32Snapshot( TH32CS_INHERIT|TH32CS_SNAPALL , 0 ) ) == INVALID_HANDLE_VALUE){
		puts("error");
		return 0;
	}

	BOOL status = Process32First( snapshot , &processInfo );
	while( status == TRUE ){
		if( lstrcmpW( name , processInfo.szExeFile ) == 0 ){
			wprintf( L"pid:%d\n" , processInfo.th32ProcessID );
			if( pList != NULL ){
				pList->push_back( processInfo.th32ProcessID );
			}
			return processInfo.th32ProcessID;
		}
		status = Process32Next( snapshot , &processInfo );
	}

	CloseHandle( snapshot );
	return 0;
}

//获取指定进程的堆信息
BOOL ListProcessHeaps(DWORD dwOwnerPID , list< pair<DWORD,DWORD> > * pList)
{
	HEAPLIST32 h1;
	HANDLE hHeapSnap = INVALID_HANDLE_VALUE;
	
	//创建指定进程下的堆快照
	hHeapSnap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, dwOwnerPID);
	if(hHeapSnap == INVALID_HANDLE_VALUE)
		return FALSE;
	
	//填充结构成员
	h1.dwSize = sizeof(HEAPLIST32);
	if(Heap32ListFirst(hHeapSnap, &h1))
	{
		do 
		{
			//堆中的一个块 
			HEAPENTRY32 he;
			ZeroMemory(&he, sizeof(HEAPENTRY32));
			he.dwSize = sizeof(HEAPENTRY32);

			//遍历当前进程,指定堆ID下所有块
			if(Heap32First(&he, h1.th32ProcessID, h1.th32HeapID))
			{
				printf("\nHeap ID: %d\n", h1.th32HeapID);
				do
				{ 
					printf("Block size: %8x , Address: %8p\n", he.dwBlockSize,he.dwAddress);
					pList->push_back( pair<DWORD,DWORD>( he.dwAddress , he.dwBlockSize) );
					he.dwSize = sizeof(HEAPENTRY32);
				}
				while(Heap32Next(&he));
			}
			h1.dwSize = sizeof(HEAPLIST32);
		}
		while(Heap32ListNext(hHeapSnap, &h1));
	}

	CloseHandle(hHeapSnap);
	return TRUE;
}

//获取指定虚拟地址的数据
DWORD getData( DWORD pid , DWORD baseAddress , DWORD size , void * buf){
	HANDLE process;
	SIZE_T count = 0;

	process = OpenProcess(  PROCESS_ALL_ACCESS , false , pid );
	if( process == 0 ){
		puts("open process error");
		return -1;
	}

	 DWORD oldProt, newProt = 0;
	 VirtualProtectEx( process , 0 , baseAddress , newProt , &oldProt );

	 if(ReadProcessMemory( process , (LPCVOID)baseAddress , buf , size , &count )){
		 //puts("get success");
	}

	//DWORD e = GetLastError();
	VirtualProtectEx( process , 0 , baseAddress , oldProt , &newProt );
	CloseHandle( process );
	return count;
}

//在堆上查找.
DWORD processList( list< pair<DWORD,DWORD> > * pHeapList , list<DWORD> * pAddrList , DWORD pid ,void * data , DWORD size){
	list<pair<DWORD,DWORD>>::iterator it = pHeapList->begin();
	list<pair<DWORD,DWORD>>::iterator end = pHeapList->end();
	DWORD count = 0;
	char * buf = NULL;

	puts("processList start");

	while( it != end ){
		buf = (char *)malloc( sizeof(char) * it->second );

		if( getData( pid , it->first , it->second , buf ) == it->second ){
			for( DWORD i = 0 ; i < it->second ; i ++ ){
				if( memcmp( buf + i , data , size ) == 0 ){
					printf("at:%p\n" , it->first + i );
					pAddrList->push_back( (DWORD)( it->first + i ) );
					++ count;
				}
			}
		}

		free( buf );
		++ it;
	}

	return count;
}

//获取基地址
DWORD getBaseAddress( DWORD pid , WCHAR * wstr){
	HANDLE snapshot;
	MODULEENTRY32 moduleEntry32;
	moduleEntry32.dwSize = sizeof( moduleEntry32 );

	if(( snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE , pid ) ) == INVALID_HANDLE_VALUE){
		puts("error");
		return 0;
	}

	BOOL status = Module32First( snapshot , &moduleEntry32 );
	while( status ){
		if( lstrcmp( wstr , moduleEntry32.szModule ) == 0 ){
			CloseHandle( snapshot );
			return (DWORD)moduleEntry32.hModule;
		}
		status = Module32Next( snapshot , &moduleEntry32 );
	}

	CloseHandle( snapshot );
	return 0;
}

void getModule( DWORD pid ){
	HANDLE snapshot;
	MODULEENTRY32 moduleEntry32;
	moduleEntry32.dwSize = sizeof( moduleEntry32 );

	if(( snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE , pid ) ) == INVALID_HANDLE_VALUE){
		puts("error");
		return ;
	}

	BOOL status = Module32First( snapshot , &moduleEntry32 );
	while( status ){
		wprintf( L"address:%08x %s %s\n" ,moduleEntry32.hModule ,moduleEntry32.szModule,moduleEntry32.szExePath);
		status = Module32Next( snapshot , &moduleEntry32 );
	}

	CloseHandle( snapshot );
}

//未实现的功能有挂起与恢复进程，获取进程栈
int main( void ){
	DWORD pid = getPidByName(L"hello.exe" , NULL);
	getModule( pid );
	list< pair<DWORD,DWORD> > heapList;
	list<DWORD> addrList;
	int f = 0x12345678;

	//ListProcessHeaps( pid , &heapList );
	//processList( &heapList , &addrList , pid , &f , sizeof(int) );

	return 0;
}