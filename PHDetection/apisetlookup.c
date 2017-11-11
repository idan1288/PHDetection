#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <sal.h>
#include <assert.h>
/*
#ifdef _X86_
#error "This snippet only build in 64-bit due to heavy use of uintptr arithmetics."
#endif
*/

// don't include <winternl.h> since their
// _PEB struct definition clash with ours.
// Instead use Processhacker's phnt internals.
#include "phnt_ntdef.h"

#pragma comment(lib, "ntdll.lib")

// The api set resolution rely on ntdll.lib internals to
// query the PEB.ApiSet member for the API_NAMESPACE struct
// and RtlCompareUnicodeStrings for strings comparisons
#pragma region ntdll internals

const NTSTATUS STATUS_SUCCESS = 0;

typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		};
	};

	HANDLE Mutant;

	PVOID ImageBaseAddress;
	/*PPEB_LDR_DATA*/ void* Ldr;
	/*PRTL_USER_PROCESS_PARAMETERS*/ void* ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ReservedBits0 : 25;
		};
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, *PPEB;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
} PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

_Must_inspect_result_
NTSYSAPI
LONG
NTAPI
RtlCompareUnicodeStrings(
	_In_reads_(String1Length) PWCH String1,
	_In_ SIZE_T String1Length,
	_In_reads_(String2Length) PWCH String2,
	_In_ SIZE_T String2Length,
	_In_ BOOLEAN CaseInSensitive
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
);
#pragma endregion ntdll internals


// Unlike ntdll internals, the following
// structures and functions are not even exported
// by ntdll.lib. Only public symbols exists for some.
//
// API_SET_XXX structs are copied from https://github.com/zodiacon/WindowsInternals/blob/master/APISetMap/ApiSet.h
// while functions were manually reversed (with the help of HexRays).
#pragma region api set internals

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


const uint64_t API_ = (uint64_t)0x2D004900500041; // L"api-"
const uint64_t EXT_ = (uint64_t)0x2D005400580045; // L"ext-";

// wordcount = bytecount / sizeof(wchar)
#define GET_WCHAR_COUNT(ByteLen) ((ByteLen) >> 1) 

#define GET_API_SET_NAMESPACE_ENTRY(ApiNamespace, HashIndex) ((API_SET_NAMESPACE_ENTRY *)((uintptr_t)ApiNamespace + HashIndex*sizeof(API_SET_NAMESPACE_ENTRY) + ApiNamespace->EntryOffset))
#define GET_API_SET_VALUE_ENTRY(ApiNamespace, Entry, Index) ((API_SET_VALUE_ENTRY *)((uintptr_t)ApiNamespace + Index*sizeof(API_SET_VALUE_ENTRY) + Entry->ValueOffset))
#define GET_API_SET_VALUE_NAME(ApiNamespace, _Entry) ((PWCHAR)((uintptr_t)ApiNamespace + _Entry->NameOffset))
#define GET_API_SET_VALUE_VALUE(ApiNamespace, _Entry) ((PWCHAR)((uintptr_t)ApiNamespace + _Entry->ValueOffset))
#define GET_API_SET_HASH_ENTRY(ApiNamespace, HashIndex) ((API_SET_HASH_ENTRY*)((uintptr_t)ApiNamespace + ApiNamespace->HashOffset  + sizeof(uint64_t) * HashIndex))

PAPI_SET_NAMESPACE_ENTRY 
__fastcall ApiSetpSearchForApiSet(
	_In_ PAPI_SET_NAMESPACE ApiNamespace,
	_In_ PWCHAR ApiNameToResolve, 
	_In_ uint16_t ApiNameToResolveSize
)
{
	
	if (!ApiNameToResolveSize)
		return NULL;

	// HashKey = Hash(ApiNameToResolve.ToLower())	
	ULONG HashKey = 0;
	for (auto i = 0; i < ApiNameToResolveSize; i++)
	{
		WCHAR CurrentChar = ApiNameToResolve[i];
		CharLowerW(&CurrentChar);
		HashKey = HashKey * ApiNamespace->HashFactor + CurrentChar;
	}
	

	int ApiSetEntryCount = ApiNamespace->Count - 1;
	if (ApiSetEntryCount < 0)
		return NULL;


	// HashTable.get("apiset-name") -> HashIndex
	int HashCounter = 0;
	int HashIndex;
	while (1)
	{
		HashIndex = (ApiSetEntryCount + HashCounter) >> 1;
		
		if (HashKey < GET_API_SET_HASH_ENTRY(ApiNamespace, HashIndex)->Hash)
		{
			ApiSetEntryCount = HashIndex - 1;
			goto CHECK_HASH_COUNTER;
		}

		
		if (HashKey == GET_API_SET_HASH_ENTRY(ApiNamespace, HashIndex)->Hash)
			break;

		HashCounter = HashIndex + 1;

	CHECK_HASH_COUNTER:
		if (HashCounter > ApiSetEntryCount)
			return NULL;
	}

	API_SET_NAMESPACE_ENTRY *FoundEntry = GET_API_SET_NAMESPACE_ENTRY(
		ApiNamespace, 
		GET_API_SET_HASH_ENTRY(ApiNamespace, HashIndex)->Index
	);


	if (!FoundEntry)
		return NULL;

	// Final check on apiset library name in order to make sure we didn't collide with another hash bucket.
	if (0 == RtlCompareUnicodeStrings(
		/* _In_ PWCHAR */ ApiNameToResolve,
		/* _In_ SHORT  */ ApiNameToResolveSize,
		/* _In_ PWCHAR */ GET_API_SET_VALUE_NAME(ApiNamespace, FoundEntry),
		/* _In_ SHORT  */ GET_WCHAR_COUNT(FoundEntry->HashedLength),
		TRUE              // Ignore case
	)) {
		return FoundEntry;
	}


	return NULL;
}

PAPI_SET_VALUE_ENTRY 
__stdcall ApiSetpSearchForApiSetHost(
	_In_ PAPI_SET_NAMESPACE_ENTRY Entry, 
	_In_ PWCHAR *ApiToResolve,
	_In_ SHORT ApiToResolveLen,
	_In_ PAPI_SET_NAMESPACE ApiNamespace
)
{
	//__int64 _EntryValueOffset; // r12@1
	int EntryHasAlias; // ebx@1
	API_SET_VALUE_ENTRY *FoundEntry; // rdi@1
	int EntryAliasIndex; // esi@3
	API_SET_VALUE_ENTRY *AliasEntry; // r14@3
	int _result; // eax@3

	// If there is no alias, don't bother checking each one.
	FoundEntry = GET_API_SET_VALUE_ENTRY(ApiNamespace, Entry, 0);
	EntryHasAlias = Entry->ValueCount - 1;
	if (!EntryHasAlias)
		return FoundEntry;

	int Counter = 1;
	do
	{
		EntryAliasIndex = (EntryHasAlias + Counter) >> 1; // Why ?
		AliasEntry = GET_API_SET_VALUE_ENTRY(ApiNamespace, Entry, EntryAliasIndex);

		_result = RtlCompareUnicodeStrings(
			/* _In_ PWCHAR */ ApiToResolve,
			/* _In_ SHORT  */ ApiToResolveLen,
			/* _In_ PWCHAR */ GET_API_SET_VALUE_NAME(ApiNamespace, AliasEntry),
			/* _In_ SHORT  */ GET_WCHAR_COUNT(AliasEntry->NameLength),
			TRUE	// Ignore case
		);

		if (_result < 0)
		{
			EntryHasAlias = EntryAliasIndex - 1;
		}
		else
		{
			if (_result == 0)
			{
				return GET_API_SET_VALUE_ENTRY(
					ApiNamespace, 
					Entry, 
					((EntryHasAlias + Counter) >> 1) // Why ?
				);
			}

			Counter = EntryAliasIndex + 1;
		}

	} while (Counter <= EntryHasAlias);
	
	return FoundEntry;
}

NTSTATUS 
__fastcall ApiSetResolveToHost(
	_In_ PAPI_SET_NAMESPACE ApiNamespace,
	_In_ PUNICODE_STRING ApiToResolve, 
	_In_ PUNICODE_STRING ParentName, 
	_Out_ PBOOLEAN Resolved, 
	_Out_ PUNICODE_STRING Output
)
{
	NTSTATUS Status; // rax@4
	char IsResolved; // bl@1
	wchar_t *ApiSetNameBuffer; // rdx@2
	__int16 ApiSetNameWithoutExtensionWordCount; // ax@8
	API_SET_NAMESPACE_ENTRY *ResolvedEntry; // rax@9
	API_SET_VALUE_ENTRY *HostLibraryEntry; // rcx@12

	IsResolved = FALSE;	
	Output->Buffer = NULL;
	Output->Length = 0;
	Output->MaximumLength = 0;

	if (ApiToResolve->Length < wcslen(L"api-") * sizeof(WCHAR))
	{
		goto EPILOGUE;
	}

	// --------------------------
	// Check library name starts with "api-" or "ext-"
	ApiSetNameBuffer = ApiToResolve->Buffer;
	uint64_t ApiSetNameBufferPrefix = ((uint64_t*) ApiSetNameBuffer)[0] & 0xFFFFFFDFFFDFFFDF;
	if (!(ApiSetNameBufferPrefix == API_ || ApiSetNameBufferPrefix == EXT_))
	{
		goto EPILOGUE;
	}

	// ------------------------------
	// Compute word count of apiset library name without the dll suffix and anything beyond the last hyphen
	// Ex: 
	//     api-ms-win-core-apiquery-l1-1-0.dll -> wordlen(api-ms-win-core-apiquery-l1-1)
	// ------------------------------
	uintptr_t LastHyphen = (uintptr_t) wcsrchr(ApiSetNameBuffer, '-');
	ApiSetNameWithoutExtensionWordCount = (SHORT) GET_WCHAR_COUNT(LastHyphen - (uintptr_t) ApiSetNameBuffer);
	if (!ApiSetNameWithoutExtensionWordCount)
	{
		goto EPILOGUE;
	}

	// Hash table lookup
	ResolvedEntry = ApiSetpSearchForApiSet(
		ApiNamespace,
		ApiSetNameBuffer,
		ApiSetNameWithoutExtensionWordCount);
	if (!ResolvedEntry)
	{
		goto EPILOGUE;
	}

	// Look for aliases in hosts librairies if necessary
	if (ParentName && ResolvedEntry->ValueCount > 1)
	{
		HostLibraryEntry = ApiSetpSearchForApiSetHost(
			ResolvedEntry,
			(PWCHAR *) ParentName->Buffer,
			GET_WCHAR_COUNT(ParentName->Length),
			ApiNamespace
		);

		goto WRITING_RESOLVED_API;
	}

	// Output resolved host library into _Out_ UNICODE_STRING structure
	if (ResolvedEntry->ValueCount > 0)
	{
		HostLibraryEntry = GET_API_SET_VALUE_ENTRY(ApiNamespace, ResolvedEntry, 0);
	
	WRITING_RESOLVED_API:
		IsResolved = TRUE;
		Output->Buffer = GET_API_SET_VALUE_VALUE(ApiNamespace, HostLibraryEntry);
		Output->MaximumLength = (SHORT) HostLibraryEntry->ValueLength;
		Output->Length = (SHORT) HostLibraryEntry->ValueLength;
		goto EPILOGUE;
	}
	

EPILOGUE:
	Status = STATUS_SUCCESS;
	*Resolved = IsResolved;
	return Status;
}
#pragma endregion api set internals



PAPI_SET_NAMESPACE 
GetApiSetNamespace()
{
	ULONG	ReturnLength;
	PROCESS_BASIC_INFORMATION ProcessInformation;
	PAPI_SET_NAMESPACE apiSetMap = NULL;

	//	Retrieve PEB address
	if (!NT_SUCCESS(NtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessBasicInformation,
		&ProcessInformation,
		sizeof(PROCESS_BASIC_INFORMATION),
		&ReturnLength
	)))
	{
		return NULL;
	}

	//	Parsing PEB structure and locating api set map
	PPEB peb = (PPEB) ProcessInformation.PebBaseAddress;
	apiSetMap = (PAPI_SET_NAMESPACE) peb->ApiSetMap;

	return apiSetMap;
}

bool 
ResolveApiSetLibrary(
	_In_ wchar_t *ApiSetLibraryName,
	PUNICODE_STRING ResolvedHostLibrary
)
{
	PAPI_SET_NAMESPACE ApiSetNamespace = GetApiSetNamespace();
	BOOLEAN Resolved = FALSE;
	UNICODE_STRING ApiToResolve = {
		.Buffer = ApiSetLibraryName,
		.Length = (short) wcslen(ApiSetLibraryName)*sizeof(wchar_t),
		.MaximumLength = (short) wcslen(ApiSetLibraryName) * sizeof(wchar_t)
	};

	NTSTATUS Status = ApiSetResolveToHost(
		ApiSetNamespace,
		&ApiToResolve,
		NULL,
		&Resolved,
		ResolvedHostLibrary
	);

	return (NT_SUCCESS(Status) && Resolved);
	

}

#define _UNICODE_LITERAL(wchar_name_array) {								\
.Buffer = wchar_name_array,													\
.Length = (SHORT)wcslen(wchar_name_array) * sizeof(wchar_t),				\
.MaximumLength = (SHORT)wcslen(wchar_name_array) * sizeof(wchar_t)			\
}

#define UNICODE_LITERAL(wchar_name_array) _UNICODE_LITERAL(wchar_name_array)

void API_SET_UNIT_TEST(wchar_t *api_set_dll, wchar_t *host_dll)
{							
	UNICODE_STRING HostLibrary = UNICODE_LITERAL (host_dll);				
	UNICODE_STRING ApiSetLibrary = UNICODE_LITERAL (api_set_dll);				
	UNICODE_STRING ResolvedHostLibrary = {0};								
	 
	assert(true == ResolveApiSetLibrary(api_set_dll, &ResolvedHostLibrary));	
	assert(0 == RtlCompareUnicodeStrings(HostLibrary.Buffer, HostLibrary.Length >> 1, ResolvedHostLibrary.Buffer, ResolvedHostLibrary.Length >> 1, TRUE));
}

/*
int wmain(int argc, wchar_t* argv[])
{
	if (argc < 2)
	{
		wprintf(L"ApiSetLookup : test for api set resolution.\n");
		return 0;
	}

	
	// Unit testing : this may not be true on your machine (that's kinda the point of the api set schema).
	API_SET_UNIT_TEST(L"api-ms-win-crt-runtime-l1-1-0.dll", L"ucrtbase.dll");
	API_SET_UNIT_TEST(L"api-ms-win-crt-math-l1-1-0.dll", L"ucrtbase.dll");
	API_SET_UNIT_TEST(L"api-ms-win-crt-stdio-l1-1-0.dll", L"ucrtbase.dll");
	API_SET_UNIT_TEST(L"api-ms-win-core-heap-l1-1-0.dll", L"kernelbase.dll");
	API_SET_UNIT_TEST(L"api-ms-win-core-job-l1-1-0.dll", L"kernelbase.dll");
	API_SET_UNIT_TEST(L"api-ms-win-core-job-l2-1-1.dll", L"kernel32.dll");
	API_SET_UNIT_TEST(L"api-ms-win-core-registry-private-l1-1-0.dll", L"advapi32.dll");
	API_SET_UNIT_TEST(L"api-ms-win-downlevel-ole32-l1-1-1.dll", L"combase.dll");
	API_SET_UNIT_TEST(L"api-ms-win-eventing-consumer-l1-1-1.dll", L"sechost.dll");
	API_SET_UNIT_TEST(L"ext-ms-onecore-appdefaults-l1-1-0.dll", L"windows.storage.dll");
	API_SET_UNIT_TEST(L"ext-ms-win-wer-wct-l1-1-0.dll", L"wer.dll");

	wchar_t *ApiSetLibraryName = argv[1];
	UNICODE_STRING HostApi = { 0 };
	if (ResolveApiSetLibrary(ApiSetLibraryName, &HostApi))
	{

		// HostApi.Buffer is not NULL terminated (probably to save some precious bytes since it's COW in every process)
		wchar_t HostLibraryName[MAX_PATH];
		_snwprintf_s(HostLibraryName, _countof(HostLibraryName), HostApi.Length >> 1, L"%s", HostApi.Buffer);


		wprintf(L"[!] Api set library resolved : %s -> %s\n", ApiSetLibraryName, HostLibraryName);
	}
	else
	{
		wprintf(L"[x] Could not resolve Api set library : %s.\n", ApiSetLibraryName);
	}

	return 0;
}
*/