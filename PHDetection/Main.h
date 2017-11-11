#pragma once
#include <Windows.h>
#include "phnt_ntdef.h"
#include <stdbool.h>
#include <delayimp.h>
#include <vector>
#include <iostream>
#include <stdio.h>
#include <TlHelp32.h>
#include <Psapi.h>

#pragma comment(lib, "ntdll.lib")

DWORD convertAsciiToWide(char * cString, wchar_t ** wideString);
DWORD calcVAToOffset(PIMAGE_SECTION_HEADER pSecH, DWORD virtualAddressToConvert);
int apisetTrans(wchar_t * apiSetLibraryName, wchar_t ** resolvedDllName);
BOOL isExists(std::vector<wchar_t *> strVec, wchar_t * str);
std::vector<wchar_t *> detectPerProcess(std::vector<wchar_t *> diskModules, std::vector<wchar_t *> memoryModules);
BOOL freeVector(std::vector<wchar_t *> vecToDelete);
DWORD compareModules(wchar_t * processPath, BOOL is32BitProcess, DWORD processId);
/*
extern "C" {
#include "phnt_ntdef.h"
}
extern "C" {
#include "apisetlookup.c"
}*/

#define NO_DIFFS			0
#define DIFF_MODULES		1
#define DIFF_TIMESTAMPS		2


typedef struct _MODULE_INFO
{
	wchar_t * ModuleName;
	SIZE_T ModuleBaseAddr;
	SIZE_T ModuleBaseSize;
} MODULE_INFO, *PMODULE_INFO;

typedef struct _API_SET_NAMESPACE {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

typedef struct _API_SET_HASH_ENTRY {
	ULONG Hash;
	ULONG Index;
} API_SET_HASH_ENTRY, *PAPI_SET_HASH_ENTRY;

typedef struct _API_SET_NAMESPACE_ENTRY {
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG HashedLength;
	ULONG ValueOffset;
	ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY, *PAPI_SET_NAMESPACE_ENTRY;

typedef struct _API_SET_VALUE_ENTRY {
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY, *PAPI_SET_VALUE_ENTRY;

#ifdef __cplusplus
extern "C" {
#endif
bool
ResolveApiSetLibrary(
	_In_ wchar_t *ApiSetLibraryName,
	PUNICODE_STRING ResolvedHostLibrary
);


PAPI_SET_NAMESPACE
GetApiSetNamespace();


#ifdef __cplusplus
}
#endif
