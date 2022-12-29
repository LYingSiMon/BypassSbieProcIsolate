#include "Enum.h"
#include "Common.h"
#include "spdlog/spdlog.h"

#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <psapi.h>
#include <WtsApi32.h>

#pragma comment(lib,"WtsApi32.lib")

void Enum_CreateToolhelp32Snapshot()
{
	INT ProcCount = 0;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) 
	{ 
		return;
	}

	PROCESSENTRY32 process = { sizeof(PROCESSENTRY32) };
	for (BOOL flag = Process32First(hProcessSnap, &process); flag; flag = Process32Next(hProcessSnap, &process)) 
	{
		if (_wcsicmp(process.szExeFile, SELF_PROCNAME_W) == 0)
		{
			ProcCount++;
		}
	}

	if (ProcCount > 1)
	{
		spdlog::error("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
	else
	{
		spdlog::info("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
}

void Enum_EnumProcesses()
{
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	HANDLE hProcess = NULL;
	WCHAR FilePath[MAX_PATH] = { 0 };
	INT ProcCount = 0;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return;
	}

	cProcesses = cbNeeded / sizeof(DWORD);
	for (UINT i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, aProcesses[i]);
			if (NULL != hProcess)
			{
				memset(FilePath, 0, MAX_PATH);
				GetModuleFileNameExW(hProcess, 0, FilePath, MAX_PATH);
				if (wcsstr(FilePath, SELF_PROCNAME_W) != 0)
				{
					ProcCount++;
				}
			}
		}
	}

	if (ProcCount > 1)
	{
		spdlog::error("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
	else
	{
		spdlog::info("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
}

void Enum_WTSEnumerateProcess()
{
	INT ProcCount = 0;
	DWORD dwCount = 0;
	PWTS_PROCESS_INFO pi = { 0 };
	if (WTSEnumerateProcesses(NULL,0,1,&pi,&dwCount))
	{
		for (UINT i = 0; i < dwCount; i++) 
		{
			if (_wcsicmp(pi[i].pProcessName, SELF_PROCNAME_W) == 0)
			{
				ProcCount++;
			}
		}
	}

	if (ProcCount > 1)
	{
		spdlog::error("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
	else
	{
		spdlog::info("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
}

void Enum_ZwQuerySystemInformation()
{
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)   
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)   
#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004L)   
	typedef struct _LSA_UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;

	} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG NextEntryOffset;
		ULONG ThreadCount;
		ULONG Reserved1[6];
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ProcessName;
		long BasePriority;
		ULONG ProcessId;
		ULONG InheritedFromProcessId;
		ULONG HandleCount;
		ULONG Reserved2[2];
		SIZE_T  VmCounters;
		IO_COUNTERS IoCounters;
		LARGE_INTEGER Threads[1];
	} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

	typedef LONG NTSTATUS;

	typedef NTSTATUS(NTAPI* P_ZwQuerySystemInformation)(
		IN ULONG SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength
		);

	HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
	if (!hNtdll)
	{
		return;
	}
	P_ZwQuerySystemInformation ZwQuerySystemInformation = (P_ZwQuerySystemInformation)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
	
	INT ProcCount = 0;
	DWORD len;
	NTSTATUS result;
	PSYSTEM_PROCESS_INFORMATION spi;
	BYTE* pBuf;
	result = ZwQuerySystemInformation((UINT)5, NULL, 0, &len);
	pBuf = new BYTE[len];

	if (result == STATUS_INFO_LENGTH_MISMATCH)
	{ 
		result = ZwQuerySystemInformation(5, pBuf, len, &len);
		if (result == STATUS_SUCCESS)
		{
			PSYSTEM_PROCESS_INFORMATION pre = spi = (PSYSTEM_PROCESS_INFORMATION)pBuf;
			do
			{
				if (spi->ProcessName.Buffer)
				{
					if (_wcsicmp(spi->ProcessName.Buffer, SELF_PROCNAME_W) == 0)
					{
						ProcCount++;
					}
				}

				pre = spi;
				spi = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)spi + spi->NextEntryOffset);
			} while (pre->NextEntryOffset != 0);
		}
	}
	
	if (ProcCount > 1)
	{
		spdlog::error("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
	else
	{
		spdlog::info("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
}

void Enum_OpenProcess()
{
	INT ProcCount = 0;
	HANDLE hProcess = NULL;
	WCHAR FilePath[MAX_PATH] = { 0 };

	for (UINT i = 0; i < 100000; i += 4) 
	{
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, i);
		if (NULL != hProcess)
		{
			memset(FilePath, 0, MAX_PATH);
			GetModuleFileNameExW(hProcess, 0, FilePath, MAX_PATH);
			if (wcsstr(FilePath, SELF_PROCNAME_W) != 0)
			{
				ProcCount++;
			}
		}
	}

	if (ProcCount > 1)
	{
		spdlog::error("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
	else
	{
		spdlog::info("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
}