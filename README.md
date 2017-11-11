# PHDetection

PHDetection is a live technique that detects Process Hollowing in Windows.

## Introduction
Some malwares today use the "Process Hollowing" technique to "hide" themselves from the users and the cyber investigations teams.
There are many ways to detect "Process Hollowing" today. Most of them, if not all of them, are based on memory forensics.
PHDetection  is a tool that you can run on a live system, or your entire network, to detect and find hollowed processes.
## How it works
PHDetection looks for modules that the original EXE is depends on, and check if they are loaded in the process memory.
If we find a modules that the EXE depends on (if it's written on the EXE's IAT) but we don't find it in the process memory, that indicate that the process is hollowed and have been replaced with another EXE.
There are some EXE files that don't depend on many modules on the IAT, so we are going to parse also the Delay Load Import Table.
## Delay Load Import – What is it?
From MSDN:
> The Visual C++ linker now supports the delayed loading of DLLs. This relieves you of the need to use the Windows SDK functions LoadLibrary and GetProcAddress to implement DLL delayed loading.
> Before Visual C++ 6.0, the only way to load a DLL at run time was by using LoadLibrary and GetProcAddress; the operating system would load the DLL when the executable or DLL using it was loaded.
> Beginning with Visual C++ 6.0, when statically linking with a DLL, the linker provides  options to delay load the DLL until the program calls a function in that DLL.

Some EXE file was compiled with Delay Load Import flag, so we are going to parse that table also. 
PHDetection scans all running processes on the system, and lists for each process it's memory loaded modules.
For each process, it detects the EXE file on the disk, and parses the import table and the delayed import table of the executable file.
If it finds a module from the IAT that isn't loaded to the memory, it prints a message that it detected a hollowed process.
If it finds a module from the Delayed import table that isn't loaded to the memory, it isn't enough to indicate that this process was hollowed.
So we are going to check the EXE's pNtH->FileHeader.TimeDateStamp and compare it to the memory's loaded EXE.
If they are different, we found a hollowed process.
## Assumptions
* The malware writer didn't load the modules that the original EXE is depends on.
* The malware writer didn't change the timestamp header value in the hollowed process to the one that the original EXE had on the disk.

## Usage
Just run the file according to your windows version (32/64 bit) with admin privileges.

## Credits
Apiset resolving:
https://gist.github.com/lucasg/9aa464b95b4b7344cb0cddbdb4214b25


