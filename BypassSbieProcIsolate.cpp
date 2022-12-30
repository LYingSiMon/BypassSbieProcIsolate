// BypassSbieProcIsolate.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "Enum.h"
#include "spdlog/spdlog.h"

#include <Windows.h>
#include <stdio.h>

/* 思路：
* 1.借助 APIMonitor ，或 msdn 把所有的 API 都看一遍，找到可能利用的 API，写代码测试。
* 2.重看 Windows 核心编程，找突破口
*/

void Test_Enum()
{
    spdlog::info("============== [{}] ==============", __FUNCTION__);

    // 进程名遍历
    Enum_CreateToolhelp32Snapshot();
    Enum_EnumProcesses();
    Enum_WTSEnumerateProcess();
    Enum_ZwQuerySystemInformation();
    Enum_DirectSystemCalls();
    Enum_OpenProcess();
    Enum_PerformanceData();
    Enum_PerformanceDataHelper();

    // 进程特征遍历
    Enum_EnumWindows();
    Enum_EnumChildWindows();
    Enum_EnumDesktopWindows();
    Enum_GetWindow();
    Enum_EnumThreadWindows();
    Enum_HotKey();
    Enum_Test();
}

int main()
{
    Test_Enum();

    getchar();
}
