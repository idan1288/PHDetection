#include "Main.h"

//#define debug TRUE

DWORD parseTimeStamp(BYTE * Pe, BOOL is32BitProcess)
{

	PIMAGE_DOS_HEADER		pDosH;
	PIMAGE_NT_HEADERS32		pNtH32;
	PIMAGE_NT_HEADERS64		pNtH64;

	// Get the dos header
	pDosH = (PIMAGE_DOS_HEADER)Pe;
	// Get the nt header
	//pNtH = (PIMAGE_NT_HEADERS)(FileBuffer + pDosH->e_lfanew); 

	// Return the timestamp
	if (is32BitProcess)
	{
		pNtH32 = (PIMAGE_NT_HEADERS32)(Pe + pDosH->e_lfanew);
		return pNtH32->FileHeader.TimeDateStamp;
	}
	else
	{
		pNtH64 = (PIMAGE_NT_HEADERS64)(Pe + pDosH->e_lfanew);
		return pNtH64->FileHeader.TimeDateStamp;
	}

}

BYTE * getMemoryPEBuffer(SIZE_T baseAddress, DWORD sizeOfBA, DWORD pid, BOOL is32BitProcess)
{
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
	BYTE * peImMemory = (BYTE *)malloc(sizeOfBA);
	SIZE_T bytesRead;

	// Read the memory mapped image
	if (!ReadProcessMemory(hProcess, (LPCVOID)baseAddress, peImMemory, sizeOfBA, &bytesRead))
		return FALSE;
	CloseHandle(hProcess);

	return peImMemory;
}

std::vector<wchar_t *> memoryLoadedModules(DWORD processId, BOOL is32BitProcess)
{
	HANDLE snapshot;
	MODULEENTRY32W moduleEntry;
	std::vector<wchar_t *> memoryDllVector;
	wchar_t * dllModuleW = NULL;
	int getLastError;

	// Create snapshot of dlls in process
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		getLastError = GetLastError();
		return memoryDllVector;
	}
	moduleEntry.dwSize = sizeof(MODULEENTRY32W);

	// List the Dlls
	if (!Module32FirstW(snapshot, &moduleEntry))
	{
		CloseHandle(snapshot);
		return memoryDllVector;
	}
	do
	{
		// Adding the dll to the list

		if (!isExists(memoryDllVector, moduleEntry.szModule))
		{
			dllModuleW = (wchar_t *)malloc((wcslen(moduleEntry.szModule) + 1) * 2);
			lstrcpyW(dllModuleW, moduleEntry.szModule);
			memoryDllVector.push_back(dllModuleW);
		}
	} while (Module32NextW(snapshot, &moduleEntry));

	CloseHandle(snapshot);

	return memoryDllVector;
}

BYTE * GetFileBuffer(wchar_t * filePath)
{
	HANDLE hFile;
	DWORD FileSize, bytesRead;

	// Get the handle to the file to read
	hFile = CreateFileW(filePath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	// Calculate the size of the file
	FileSize = GetFileSize(hFile, NULL);
	BYTE * FileBuffer = (BYTE *)malloc(FileSize);
	if (!FileBuffer)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	// Read the file
	if (!ReadFile(hFile, FileBuffer, FileSize, &bytesRead, NULL))
	{
		CloseHandle(hFile);
		free(FileBuffer);
		return FALSE;
	}
	CloseHandle(hFile);
	return FileBuffer;
}

std::vector<wchar_t *> diskRegularModules(wchar_t * filePath, BOOL is32BitProcess)
{
	// Read the file
	BYTE * FileBuffer = GetFileBuffer(filePath);
	std::vector<wchar_t *> diskModulesVector;
	if (!FileBuffer)
	{
		return diskModulesVector;
	}

	PIMAGE_DOS_HEADER		pDosH;
	PIMAGE_NT_HEADERS32		pNtH32;
	PIMAGE_NT_HEADERS64		pNtH64;
	PIMAGE_SECTION_HEADER	pSecH;
	IMAGE_DATA_DIRECTORY	importTableDirectory;
	wchar_t * moduleWchar;

	// Get the dos header
	pDosH = (PIMAGE_DOS_HEADER)FileBuffer; 

	// Get the nt header
	// Get the section header
	// Get the Import Table
	if (is32BitProcess)
	{
		pNtH32 = (PIMAGE_NT_HEADERS32)(FileBuffer + pDosH->e_lfanew);
		pSecH = (PIMAGE_SECTION_HEADER)(FileBuffer + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
		importTableDirectory = pNtH32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	}
	else
	{
		pNtH64 = (PIMAGE_NT_HEADERS64)(FileBuffer + pDosH->e_lfanew);
		pSecH = (PIMAGE_SECTION_HEADER)(FileBuffer + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
		importTableDirectory = pNtH64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	}

	// Get the Import Table or Delayed import table

	// No import table
	if (!importTableDirectory.VirtualAddress)
	{
		free(FileBuffer);
		return diskModulesVector;
	}

	// Calculate the Virtual Address to Offset of the Import Table
	DWORD vaToOffset = calcVAToOffset(pSecH, importTableDirectory.VirtualAddress);

	PIMAGE_IMPORT_DESCRIPTOR importTable =(PIMAGE_IMPORT_DESCRIPTOR)(FileBuffer + importTableDirectory.VirtualAddress - vaToOffset);

	// List disk modules
	do {
		char * ansiStr = (char *)(importTable->Name + FileBuffer - vaToOffset);

#ifdef debug 
		printf("%s\n", ansiStr);
#endif // DEBUG


		convertAsciiToWide(ansiStr, &moduleWchar);

		// Translate the apisets
		if (strstr(ansiStr, "api-ms-") || strstr(ansiStr, "ext-ms-"))
		{
			wchar_t * moduleWcharOld = moduleWchar;
			if (apisetTrans(moduleWchar, &moduleWchar))
				wprintf(L"There was a problem with the ApiSetTranslate\n");
			else
			{
				free(moduleWcharOld);
			}
		}

		if (!isExists(diskModulesVector, moduleWchar))
		{

			// Add the modules to the vector
			diskModulesVector.push_back(moduleWchar);
#ifdef debug
			wprintf(L"%s\n", moduleWchar);
#endif // DEBUG
		}
		else
			free(moduleWchar);

		importTable++;
	} while (*(DWORD *)importTable != 0);
	
	free(FileBuffer);
	return diskModulesVector;
}

std::vector<wchar_t *> diskDelayedModules(wchar_t * filePath, BOOL is32BitProcess)
{
	/* 
	To get to the dll string:
	datadirectory[13].virtualaddress
	then we need to find the offset to the file (will be in the .text section)
	the in PImgDelayDescr->rvaDLLName we will have to find that RVA
	we have to itterate on the PImgDelayDescr until it filled with 0's
	*/

	// Read the file
	BYTE * FileBuffer = GetFileBuffer(filePath);
	std::vector<wchar_t *> diskDelayModuleVector;
	if (!FileBuffer)
	{
		return diskDelayModuleVector;
	}
	PIMAGE_DOS_HEADER		pDosH;
	PIMAGE_NT_HEADERS32		pNtH32;
	PIMAGE_NT_HEADERS64		pNtH64;
	PIMAGE_SECTION_HEADER	pSecH;
	IMAGE_DATA_DIRECTORY delayedImportTableDirectory;
	wchar_t * wDllName;

	// Dos header

	pDosH = (PIMAGE_DOS_HEADER)FileBuffer;

	// Get the nt header
	// Get the section header
	// Get the Delayed Import Table

	if (is32BitProcess)
	{
		pNtH32 = (PIMAGE_NT_HEADERS32)(FileBuffer + pDosH->e_lfanew);
		pSecH = (PIMAGE_SECTION_HEADER)(FileBuffer + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
		delayedImportTableDirectory = pNtH32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	}
	else
	{
		pNtH64 = (PIMAGE_NT_HEADERS64)(FileBuffer + pDosH->e_lfanew);
		pSecH = (PIMAGE_SECTION_HEADER)(FileBuffer + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
		delayedImportTableDirectory = pNtH64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	}
	
	if (!delayedImportTableDirectory.VirtualAddress)
	{
		free(FileBuffer);
		return diskDelayModuleVector;
	}

	// Search to find in which section the delayed import table is
	DWORD delayedITVaToOffset = calcVAToOffset(pSecH, delayedImportTableDirectory.VirtualAddress);
	PImgDelayDescr delayedImportTable = (PImgDelayDescr)(FileBuffer + delayedImportTableDirectory.VirtualAddress - delayedITVaToOffset);
	
	// List the delayed modules
	do
	{
		DWORD dllNameVaToOffset = calcVAToOffset(pSecH, delayedImportTable->rvaDLLName);
		char * asciiDllName = (char *)(FileBuffer + delayedImportTable->rvaDLLName - dllNameVaToOffset);
		convertAsciiToWide(asciiDllName, &wDllName);

		// Translate the apisets 
		if (strstr(asciiDllName, "api-ms-") || strstr(asciiDllName, "ext-ms-"))
		{
			wchar_t * moduleWcharOld = wDllName;
			if (apisetTrans(wDllName, &wDllName))
				wprintf(L"There was a problem with the ApiSetTranslate\n");
			else
			{
				free(moduleWcharOld);
			}
		}

		// Add the delayed modules to the vector
		if (!isExists(diskDelayModuleVector, wDllName))
			diskDelayModuleVector.push_back(wDllName);
		else
			free(wDllName);

		delayedImportTable++;
	} while (*(DWORD *)delayedImportTable);

	free(FileBuffer);
	return diskDelayModuleVector;
}

DWORD convertAsciiToWide(char * cString, wchar_t ** wideString)
{
	DWORD wideStringLength = (strlen(cString)+1)*2;
	*wideString = (wchar_t *)malloc(wideStringLength);
	ZeroMemory(*wideString, wideStringLength);
	return MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, cString, -1, *wideString, wideStringLength / 2);
}


DWORD calcVAToOffset(PIMAGE_SECTION_HEADER pSecH, DWORD virtualAddressToConvert)
{
	int difInSec;
	do
	{
		pSecH++;
		difInSec = (DWORD)pSecH->VirtualAddress - virtualAddressToConvert;
	} while (difInSec <= 0 && *(DWORD*)pSecH != 0);
	pSecH--;

	return pSecH->VirtualAddress - pSecH->PointerToRawData;
}

/*
std::vector<wchar_t *> diskModules(wchar_t * filePath, BOOL is32BitProcess)
{
	std::vector<wchar_t *> diskModuleVector, delayedModuleVector;

	diskModuleVector = diskRegularModules(filePath, is32BitProcess);
	delayedModuleVector = diskDelayedModules(filePath, is32BitProcess);

	if (delayedModuleVector.empty())
		return diskModuleVector;

	for (std::vector<wchar_t *>::iterator it = delayedModuleVector.begin(); it != delayedModuleVector.end(); it++)
	{
		if (!isExists(diskModuleVector, *it))
			diskModuleVector.push_back(*it);
	}

	return diskModuleVector;
}
*/

BOOL scanProcesses()
{
	HANDLE processSnap;
	PROCESSENTRY32W pe32;
	HANDLE hProcess;
	BOOL is32BitProcess = FALSE;
	wchar_t processPath[(MAX_PATH + 1) * 2];
	DWORD processPathLength = MAX_PATH;
	std::vector<wchar_t *> diskModuleVector, delayedModuleVector, memoryModuleVector, suspiciousModule;

	// List all processes on the system
	processSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32W);
	if (!Process32FirstW(processSnap, &pe32))
	{
		CloseHandle(processSnap);
		return FALSE;
	}
	do
	{
		// Get the full path of the process
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
		if (!hProcess)
			continue;
		QueryFullProcessImageNameW(hProcess, 0, processPath, &processPathLength);

		// Checks if the process is 32 bit
#ifdef _WIN64
		IsWow64Process(hProcess, &is32BitProcess);
#endif

#ifdef _X86_
		is32BitProcess = TRUE;
#endif

		// Get the import table modules
		diskModuleVector = diskRegularModules(processPath, is32BitProcess);

		// Get the delayed import table modules
		delayedModuleVector = diskDelayedModules(processPath, is32BitProcess);

		// Get the memory loaded modules
		memoryModuleVector = memoryLoadedModules(pe32.th32ProcessID, is32BitProcess);
		if (!diskModuleVector.empty() && !memoryModuleVector.empty())
		{
			// Checks for a suspicious module by comparing between modules from the import table and the Loaded Modules
			suspiciousModule = detectPerProcess(diskModuleVector, memoryModuleVector);
			if (!suspiciousModule.empty())
			{
				// Found a suspicious process
				for(std::vector<wchar_t *>::iterator it=suspiciousModule.begin(); it != suspiciousModule.end(); ++it)
					wprintf(L"%s was on the disk but not in the memory, PID: %d, Name: %s\n", *it, pe32.th32ProcessID, pe32.szExeFile);
			}
		}

		if(!delayedModuleVector.empty() && !memoryModuleVector.empty())
		{
			// Checks for a suspicious module by comparing between modules from the Delayed Import Table and the Loaded Modules
			suspiciousModule = detectPerProcess(delayedModuleVector, memoryModuleVector);
			if (!suspiciousModule.empty())
			{
				/*	
					Found a suspicious process.
					But this check is not always indicates a detection of Process Hollowing.
					To confirm that this was defenatly Process Hollowing we have to check some of the headers of the EXE
					I chose to compare the Time Stamps from the disk's EXE between the memory's EXE
				*/
				DWORD retCode = compareModules(processPath, is32BitProcess, pe32.th32ProcessID);
				wchar_t * reason;
				switch (retCode)
				{
				case DIFF_MODULES:
					reason = L"Found more than one Exe with the same name with different BaseAddress.";
					break;
				case DIFF_TIMESTAMPS:
					reason = L"Found an Exe Module with a different timestamp in memory from the disk.";
					break;
				}

				if (retCode)
				{
					for (std::vector<wchar_t *>::iterator it = suspiciousModule.begin(); it != suspiciousModule.end(); ++it)
						wprintf(L"%s was on the disk but not in the memory [DelayedImports], PID: %d, Name: %s\nReason: %s\n", *it, pe32.th32ProcessID, pe32.szExeFile, reason);
				}
			}
		}
		

		//freeVector(suspiciousModule);
		freeVector(delayedModuleVector);
		freeVector(diskModuleVector);
		freeVector(memoryModuleVector);
		ZeroMemory(processPath, (processPathLength + 1) * 2);
		processPathLength = MAX_PATH;
		CloseHandle(hProcess);
	} while (Process32NextW(processSnap, &pe32));

	return TRUE;
}

PMODULE_INFO createModuleInfo(wchar_t * moduleName, SIZE_T baseAddr, SIZE_T baseSize)
{
	PMODULE_INFO moduleInfo = (PMODULE_INFO)malloc(sizeof(MODULE_INFO));

	moduleInfo->ModuleBaseAddr = baseAddr;
	moduleInfo->ModuleBaseSize = baseSize;
	moduleInfo->ModuleName = (wchar_t *)malloc((wcslen(moduleName) + 1) * 2);
	wcscpy(moduleInfo->ModuleName, moduleName);

	return moduleInfo;
}

std::vector<PMODULE_INFO> getModule32FirstW(DWORD processId, BOOL is32BitProcess)
{
	HANDLE snapshot;
	std::vector<PMODULE_INFO> exeModules;
	PMODULE_INFO moduleInfo;
	MODULEENTRY32W moduleEntry;
	DWORD flags = TH32CS_SNAPMODULE;

#ifdef _WIN64
	if (is32BitProcess)
		flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
#endif

	// Create snapshot of dlls in process
	snapshot = CreateToolhelp32Snapshot(flags, processId);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		return exeModules;
	}
	moduleEntry.dwSize = sizeof(MODULEENTRY32W);

	// List the Dlls
	if (!Module32FirstW(snapshot, &moduleEntry))
	{
		CloseHandle(snapshot);
		return exeModules;
	}

	do
	{
		if (!wcsicmp(wcsrchr(moduleEntry.szModule, L'.'), L".exe"))
		{
			moduleInfo = createModuleInfo(moduleEntry.szModule, (SIZE_T)moduleEntry.modBaseAddr, moduleEntry.modBaseSize);
			exeModules.push_back(moduleInfo);
		}

	} while (Module32NextW(snapshot, &moduleEntry));

	CloseHandle(snapshot);
	return exeModules;
}

BOOL isDiffrentModules(std::vector<PMODULE_INFO> modules)
{
	for (std::vector<PMODULE_INFO>::iterator it = modules.begin(); it != modules.end(); ++it)
	{
		if (!(wcsicmp(modules[0]->ModuleName,(*it)->ModuleName)) && (modules[0]->ModuleBaseAddr != (*it)->ModuleBaseAddr))
			return TRUE;
	}
	return FALSE;
}

BOOL freePmoduleVector(std::vector<PMODULE_INFO> modules)
{
	for (std::vector<PMODULE_INFO>::iterator it = modules.begin(); it != modules.end(); ++it)
	{
		free((*it)->ModuleName);
		free(*it);
	}
	modules.clear();
	return TRUE;
}

DWORD compareModules(wchar_t * processPath, BOOL is32BitProcess, DWORD processId)
{
	std::vector<PMODULE_INFO> modules;

	modules = getModule32FirstW(processId, is32BitProcess);
	// Get the module information from the EXE in memory
	if (modules.empty())
		return NO_DIFFS;

	// Check if the Exe modules are different
	if (modules.size() > 1)
		if (isDiffrentModules(modules))
			return DIFF_MODULES;
	
	// Read the EXE's PE from memory
	BYTE * peMemoryBuffer = getMemoryPEBuffer(modules[0]->ModuleBaseAddr, modules[0]->ModuleBaseSize , processId, is32BitProcess);

	// Free std::vector<PMODULE_INFO> modules memory
	freePmoduleVector(modules);

	// Get the timestamp from memory
	DWORD memoryTimeStamp = parseTimeStamp(peMemoryBuffer, is32BitProcess);

	// Read the EXE's PE from disk
	BYTE * peDiskBuffer = GetFileBuffer(processPath);

	// Get the timestamp from disk
	DWORD diskTimeStamp = parseTimeStamp(peDiskBuffer, is32BitProcess);

	// Compare between the timestamps
	if (memoryTimeStamp != diskTimeStamp)
	{
		free(peMemoryBuffer);
		free(peDiskBuffer);
		return DIFF_TIMESTAMPS;
	}
	free(peMemoryBuffer);
	free(peDiskBuffer);
	return NO_DIFFS;
}

// Free the strings in the vector
BOOL freeVector(std::vector<wchar_t *> vecToDelete)
{
	if (vecToDelete.empty())
		return 0;
	for (std::vector<wchar_t *>::iterator it = vecToDelete.begin(); it != vecToDelete.end(); ++it)
		free(*it);
	vecToDelete.clear();
	return 0;
}


// Check if a string exists in the vector
BOOL isExists(std::vector<wchar_t *> strVec, wchar_t * str)
{
	for (std::vector<wchar_t *>::iterator it = strVec.begin(); it != strVec.end(); ++it)
	{
		if (!lstrcmpiW(*it, str))
		{
			return TRUE;
		}
	}
	return FALSE;
}


// Find diffs between disk's module vector and memory's module vector
std::vector<wchar_t *> detectPerProcess(std::vector<wchar_t *> diskModules, std::vector<wchar_t *> memoryModules)
{
	std::vector<wchar_t *> suspiciusModules;
	for (std::vector<wchar_t *>::iterator it = diskModules.begin() ; it != diskModules.end(); ++it)
	{
		if (!isExists(memoryModules, *it))
		{
			wchar_t * suspModule = (wchar_t *)malloc((wcslen(*it) + 1) * 2);
			wcscpy(suspModule, *it);
			suspiciusModules.push_back(suspModule);
		}
	}
	return suspiciusModules;
}

// Translate apisets
int apisetTrans(wchar_t * apiSetLibraryName, wchar_t ** resolvedDllName)
{
	//wchar_t *ApiSetLibraryName = dll;
	UNICODE_STRING HostApi = { 0 };
	if (ResolveApiSetLibrary(apiSetLibraryName, &HostApi))
	{

		// HostApi.Buffer is not NULL terminated (probably to save some precious bytes since it's COW in every process)
		wchar_t HostLibraryName[(MAX_PATH + 1) * 2];
		_snwprintf_s(HostLibraryName, _countof(HostLibraryName), HostApi.Length >> 1, L"%s", HostApi.Buffer);

		*resolvedDllName = (wchar_t *)malloc((lstrlenW(HostLibraryName) + 1) * 2);
		lstrcpyW(*resolvedDllName, HostLibraryName);

		return 0;
	}
	return 1;
}


int main()
{
	scanProcesses();
	return 0;
}