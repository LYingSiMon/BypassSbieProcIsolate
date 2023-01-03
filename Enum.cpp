#include "Enum.h"
#include "Common.h"
#include "spdlog/spdlog.h"

#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <psapi.h>
#include <WtsApi32.h>
#include <tchar.h>
#include <winperf.h>
#include <map>
#include <Pdh.h>
#include <PdhMsg.h>

#pragma comment(lib,"WtsApi32.lib")
#pragma comment(lib,"Pdh.lib")

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

extern "C" ULONG _ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength);

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

void Enum_DirectSystemCalls()
{
	INT ProcCount = 0;
	DWORD len;
	NTSTATUS result;
	PSYSTEM_PROCESS_INFORMATION spi;
	BYTE* pBuf;
	result = _ZwQuerySystemInformation((UINT)5, NULL, 0, &len);
	pBuf = new BYTE[len];

	if (result == STATUS_INFO_LENGTH_MISMATCH)
	{
		result = _ZwQuerySystemInformation(5, pBuf, len, &len);
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



void Enum_PerformanceData()
{
	INT ProcCount = 0;
	BYTE  data[0x40000] = { 0 };
	DWORD cb = 0x40000, type = 0;;
	RegQueryValueExA(HKEY_PERFORMANCE_DATA, "230 232", NULL, &type, data, &cb);


	PPERF_DATA_BLOCK ppdb = (PPERF_DATA_BLOCK)data;
	PPERF_OBJECT_TYPE ppbt = (PPERF_OBJECT_TYPE)((BYTE*)data + ppdb->HeaderLength);

	UINT count_obj = 0;
	while (ppbt->ObjectNameTitleIndex != 230) 
	{
		ppbt = (PPERF_OBJECT_TYPE)(ppbt->TotalByteLength + (BYTE*)ppbt);
		if (++count_obj >= ppdb->NumObjectTypes)
		{
			return ;
		}
	}

	PPERF_COUNTER_DEFINITION ppcd = (PPERF_COUNTER_DEFINITION)(ppbt->HeaderLength + (BYTE*)ppbt);

	UINT count_counter = 0;
	while (ppcd->CounterNameTitleIndex != 784)
	{
		ppcd = (PPERF_COUNTER_DEFINITION)(ppcd->ByteLength + (BYTE*)ppcd);
		if (++count_counter >= ppbt->NumCounters)
		{
			printf("error, no pid counter found\n");
			return ;
		}
	}

	PERF_INSTANCE_DEFINITION* ppid = (PPERF_INSTANCE_DEFINITION)(ppbt->DefinitionLength + (BYTE*)ppbt);
	int count_instance = 0;
	while (ppid && ppid->ByteLength)
	{
		if (_wcsicmp((PWCHAR)(ppid->NameOffset + (BYTE*)ppid), L"BypassSbieProcIsolate") == 0)
		{
			ProcCount++;
		}
		//wprintf(L"%s %d\n", ppid->NameOffset + (BYTE*)ppid, *(DWORD*)(ppid->ByteLength + (BYTE*)ppid + ppcd->CounterOffset));

		ppid = (PERF_INSTANCE_DEFINITION*)(*(DWORD*)(ppid->ByteLength + (BYTE*)ppid) + ppid->ByteLength + (BYTE*)ppid);
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


void Enum_PerformanceDataHelper()
{
	INT ProcCount = 0;
	LPTSTR      szCounterListBuffer = NULL;
	DWORD       dwCounterListSize = 0;
	LPTSTR      szInstanceListBuffer = NULL;
	DWORD       dwInstanceListSize = 0;
	BOOL pass = FALSE;
	PDH_STATUS pdhStatus = PdhEnumObjectItems(NULL, NULL, TEXT("Process"),
		szCounterListBuffer, &dwCounterListSize, szInstanceListBuffer,
		&dwInstanceListSize, PERF_DETAIL_WIZARD, 0);
	if (pdhStatus != ERROR_SUCCESS)
	{
		szCounterListBuffer = (LPTSTR)malloc((dwCounterListSize * sizeof(TCHAR)));
		szInstanceListBuffer = (LPTSTR)malloc((dwInstanceListSize * sizeof(TCHAR)));
		pdhStatus = PdhEnumObjectItems(NULL, NULL, TEXT("Process"),
			szCounterListBuffer, &dwCounterListSize, szInstanceListBuffer,
			&dwInstanceListSize, PERF_DETAIL_WIZARD, 0);
		if (pdhStatus == ERROR_SUCCESS)
		{
			pass = TRUE;
			LPTSTR  pInst = szInstanceListBuffer;

			for (; *pInst != 0; pInst += lstrlen(pInst) + 1)
			{
				if (_wcsicmp(pInst, L"System") && _wcsicmp(pInst, L"Idle") &&
					_wcsicmp(pInst, L"_Total"))
				{
					// GetPIDCounterValue(pInst)   :https://blog.51cto.com/u_15127644/4028515
					// pInst
					if (_wcsicmp(pInst, L"BypassSbieProcIsolate") == 0)
					{
						ProcCount++;
					}
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

	return ;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	INT* pProcCount = (INT*)lParam;
	WCHAR WndText[MAX_PATH] = { 0 };
	GetWindowText(hwnd, WndText, MAX_PATH);
	
	//printf("%S \n", WndText);
	if (wcsstr(WndText, SELF_PROCNAME_W) != 0)
	{
		*pProcCount = *pProcCount + 1;
	}

	return TRUE;
}
void Enum_EnumWindows()
{
	INT ProcCount = 0;
	EnumWindows(EnumWindowsProc ,(LPARAM)&ProcCount);

	if (ProcCount > 1)
	{
		spdlog::error("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
	else
	{
		spdlog::info("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
}

void Enum_EnumChildWindows()
{
	INT ProcCount = 0;
	HWND hdesk = (HWND)0x10010;
	if (!hdesk)
	{
		return;
	}

	EnumChildWindows(hdesk, EnumWindowsProc, (LPARAM)&ProcCount);

	if (ProcCount > 1)
	{
		spdlog::error("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
	else
	{
		spdlog::info("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
}

BOOL CALLBACK DeskEnum(LPWSTR desk, LPARAM lParam)
{
	HDESK hDesk = OpenDesktopW(desk, 0, FALSE, DESKTOP_READOBJECTS | DESKTOP_ENUMERATE);
	if (hDesk)
	{
		HDESK hCurrentDesk = GetThreadDesktop(GetCurrentThreadId());
		EnumDesktopWindows(hDesk, &EnumWindowsProc, lParam);
	}
	return TRUE;
}
BOOL CALLBACK  EnumWinStationProc(LPTSTR winsta, LPARAM lParam)
{
	HWINSTA current = GetProcessWindowStation();
	HWINSTA hWinsta = OpenWindowStationW(winsta, FALSE, WINSTA_ENUMDESKTOPS);
	if (hWinsta)
	{
		EnumDesktopsW(hWinsta, &DeskEnum, lParam);
	}
	return true;
}
void Enum_EnumDesktopWindows()
{
	INT ProcCount = 0;
	EnumWindowStationsW(&EnumWinStationProc, (LPARAM)&ProcCount);

	if (ProcCount > 1)
	{
		spdlog::error("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
	else
	{
		spdlog::info("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
}

void Enum_GetNextWindow()
{
	INT ProcCount = 0;
	HWND hDsktp = GetDesktopWindow();
	HWND hNextWnd = hDsktp;
	WCHAR szBuf[MAX_PATH] = { 0 };

	hNextWnd = GetWindow(hDsktp, GW_CHILD);
	do
	{
		GetWindowText(hNextWnd, szBuf, MAX_PATH);
		if (wcsstr(szBuf, SELF_PROCNAME_W) != 0)
		{
			ProcCount++;
		}

	} while (NULL != (hNextWnd = GetWindow(hNextWnd, GW_HWNDNEXT)));

	if (ProcCount > 1)
	{
		spdlog::error("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
	else
	{
		spdlog::info("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
}

void Enum_EnumThreadWindows()
{

	INT ProcCount = 0;

	for (int i = 0; i < 100000; i += 4)
	{
		EnumThreadWindows(i, EnumWindowsProc, (LPARAM)&ProcCount);
	}

	ProcCount /= 2;
	if (ProcCount > 1)
	{
		spdlog::error("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
	else
	{
		spdlog::info("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
}

void Enum_LoopIsWindow()
{
	// 这个遍历在 sbie 中非常耗时，但最终只能遍历到 Default IME 窗口
	return;

	INT ProcCount = 0;
	WCHAR WndText[MAX_PATH] = { 0 };
	for (ULONG_PTR i = 0; i < 0x1000000; i+= 2)
	{
		if (IsWindow((HWND)i))
		{
			memset(WndText, 0, MAX_PATH);
			GetWindowText((HWND)i, WndText, MAX_PATH);
			if (WndText[0] == L'\0')
				continue;

			if (wcsstr(WndText, SELF_PROCNAME_W) != 0)
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

void Enum_FindWindowEx()
{
	INT ProcCount = 0;
	HWND child = NULL;
	WCHAR buf[MAX_PATH];

	do {
		memset(buf, 0, MAX_PATH);
		child = FindWindowEx(NULL, child, NULL, NULL);
		GetWindowText(child, buf, MAX_PATH);

		if (wcsstr(buf, SELF_PROCNAME_W) != 0)
		{
			ProcCount++;
		}

	} while (child);

	if (ProcCount > 1)
	{
		spdlog::error("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
	else
	{
		spdlog::info("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
	}
}

void Enum_HotKey()
{
	INT ProcCount = 0;

	for (int i = 0x70; i < 0x87; ++i)
	{
		if (RegisterHotKey(NULL, 1, MOD_ALT, i))
		{
			ProcCount = i - 0x70 + 1;
			break;
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

void Enum_Test()
{
	
}