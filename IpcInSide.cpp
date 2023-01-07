#include "IpcInSide.h"
#include "spdlog/spdlog.h"

#include <Windows.h>
#include <stdio.h>

#define PIPE_NAME L"\\\\.\\Pipe\\lysm"

DWORD WINAPI ThreadProc(PVOID pParam) {
    
    HANDLE* pHandle = (HANDLE*)pParam;

    int ProcCount = 1;
    char outBuffer[1024] = { 0 };
    char inBuffer[1024] = { 0 };
    std::string s_inBuffer;
    DWORD WriteNum = 0;
    DWORD ReadNum = 0;

    if (ConnectNamedPipe(*pHandle, NULL) == FALSE)
        return false;

    // 为了方便这里只测试一次，服务端就 break
    std::string str_recv, str_send;
    while(1)
    {
        Sleep(1000);

        //从客户端接收消息（阻塞）
        if (ReadFile(*pHandle, inBuffer, 1024, &ReadNum, NULL) == FALSE) { printf("读取数据失败！连接已断开... ErrorCode = %d \n", GetLastError()); break; }
        str_recv = inBuffer;
        if (str_recv == "count")
        {
            ProcCount++;
            str_send = std::to_string(ProcCount);

            WriteFile(*pHandle, str_send.c_str(), (DWORD)str_send.length(), &WriteNum, NULL);

            break;
        }
        else
        {
            WriteFile(*pHandle, "", (DWORD)strlen(""), &WriteNum, NULL);
        }
    }

    return 0;
}

bool CreateNamedPipe_Server()
{
	HANDLE hPipe;

    // 只有第一个创建的进程作为服务端，其余的尝试都会失败
	hPipe = CreateNamedPipe(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE, 1, 0, 0, 1000, NULL);
	if (hPipe == INVALID_HANDLE_VALUE)
		return false;

    spdlog::info("[IpcInSide_CreateNamedPipe] ProcCount:{} ", 1);

    CreateThread(0, 0, ThreadProc, &hPipe, 0, 0);
    

    return true;
}
void IpcInSide_CreateNamedPipe()
{
    // 参考代码：https://www.codenong.com/cs106911135/

    if (!CreateNamedPipe_Server())
    {
        // 不是服务端就执行客户端逻辑
        char outBuffer[1024] = { 0 };  
        char inBuffer[1024] = { 0 };   
        DWORD WriteNum = 0;
        DWORD ReadNum = 0;

        if (WaitNamedPipe(PIPE_NAME, NMPWAIT_WAIT_FOREVER) == FALSE)
            return;

        HANDLE hPipe = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hPipe == INVALID_HANDLE_VALUE)
            return;

        //向服务端发送消息
        strcpy(outBuffer, "count");
        if (WriteFile(hPipe, outBuffer, (DWORD)strlen(outBuffer), &WriteNum, NULL) == FALSE) { printf("发送数据失败！\n"); }

        //从服务端接收消息
        if (ReadFile(hPipe, inBuffer, 1024, &ReadNum, NULL) == FALSE) { printf("接收数据失败！\n");  }
        
        int ProcCount = atoi(inBuffer);
        if (ProcCount > 1)
        {
            spdlog::error("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
        }
        else
        {
            spdlog::info("[{}] ProcCount:{} ", __FUNCTION__, ProcCount);
        }
    }
}

int Count_BroadcastSystemMessage = 1;
int Count_SendMessage = 1;
int Count_PostMessage = 1;
LRESULT CALLBACK __WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {

    UINT showMyAppMsg1 = RegisterWindowMessage(L"MYAPP_LYSM");
    UINT showMyAppMsg2 = RegisterWindowMessage(L"IpcInSide_SendMessage");
    UINT showMyAppMsg3 = RegisterWindowMessage(L"IpcInSide_PostMessage");
    if (msg == showMyAppMsg1)
    {
        Count_BroadcastSystemMessage++;
        
        if (Count_BroadcastSystemMessage > 1)
        {
            spdlog::error("[IpcInSide_BroadcastSystemMessage] ProcCount:{} ", Count_BroadcastSystemMessage);
        }
        else
        {
            spdlog::info("[IpcInSide_BroadcastSystemMessage] ProcCount:{} ", Count_BroadcastSystemMessage);
        }
    }
    if (msg == showMyAppMsg2)
    {
        Count_SendMessage++;

        if (Count_SendMessage > 1)
        {
            spdlog::error("[IpcInSide_SendMessage] ProcCount:{} ", Count_SendMessage);
        }
        else
        {
            spdlog::info("[IpcInSide_SendMessage] ProcCount:{} ", Count_SendMessage);
        }
    }
    if (msg == showMyAppMsg2)
    {
        Count_PostMessage++;

        if (Count_PostMessage > 1)
        {
            spdlog::error("[IpcInSide_PostMessage] ProcCount:{} ", Count_PostMessage);
        }
        else
        {
            spdlog::info("[IpcInSide_PostMessage] ProcCount:{} ", Count_PostMessage);
        }
    }

    switch (msg) {
    case WM_CLOSE:
        break;
    default:
        break;
    }

    return DefWindowProc(hWnd, msg, wParam, lParam);
}
DWORD WINAPI ThreadMsgLoop(PVOID pParam)
{
    UINT showMyAppMsg = RegisterWindowMessage(L"MYAPP_LYSM");

    // 窗口属性初始化
    HINSTANCE hIns = GetModuleHandle(0);
    WNDCLASSEX wc;
    wc.cbSize = sizeof(wc);								// 定义结构大小
    wc.style = CS_HREDRAW | CS_VREDRAW;					// 如果改变了客户区域的宽度或高度，则重新绘制整个窗口 
    wc.cbClsExtra = 0;									// 窗口结构的附加字节数
    wc.cbWndExtra = 0;									// 窗口实例的附加字节数
    wc.hInstance = hIns;								// 本模块的实例句柄
    wc.hIcon = NULL;									// 图标的句柄
    wc.hIconSm = NULL;									// 和窗口类关联的小图标的句柄
    wc.hbrBackground = (HBRUSH)COLOR_WINDOW;			// 背景画刷的句柄
    wc.hCursor = NULL;									// 光标的句柄
    wc.lpfnWndProc = __WndProc;							// 窗口处理函数的指针
    wc.lpszMenuName = NULL;								// 指向菜单的指针
    wc.lpszClassName = L"LYSM_class";					// 指向类名称的指针

    // 为窗口注册一个窗口类
    if (!RegisterClassEx(&wc)) {
        return 0;
    }

        // 创建窗口
        HWND hWnd = CreateWindowEx(
            WS_EX_TOPMOST,				// 窗口扩展样式：顶级窗口
            L"LYSM_class",				// 窗口类名
            L"LYSM_title",				// 窗口标题
            WS_OVERLAPPEDWINDOW,		// 窗口样式：重叠窗口
            0,							// 窗口初始x坐标
            0,							// 窗口初始y坐标
            800,						// 窗口宽度
            600,						// 窗口高度
            0,							// 父窗口句柄
            0,							// 菜单句柄 
            hIns,						// 与窗口关联的模块实例的句柄
            0							// 用来传递给窗口WM_CREATE消息
        );

        UpdateWindow(hWnd);
        ShowWindow(hWnd, SW_HIDE);

        MSG msg = { 0 };
        while (msg.message != WM_QUIT) {

            if (msg.message == showMyAppMsg)
            {
                //printf("showMyAppMsg \n");
            }

            if (PeekMessage(&msg, 0, 0, 0, PM_REMOVE)) {
                DispatchMessage(&msg);
            }
        }

        return 0;
 }

void IpcInSide_BroadcastSystemMessage()
{
    // BroadcastSystemMessageEx 同理

    CreateThread(0, 0, ThreadMsgLoop, 0, 0, 0);

    DWORD dwRecipients = BSM_APPLICATIONS; 
    static UINT showMyAppMsg = RegisterWindowMessage(L"MYAPP_LYSM");
    if (!BroadcastSystemMessage(BSF_POSTMESSAGE, &dwRecipients, showMyAppMsg, 0, 0))
    {
        return;
    }
}

void IpcInSide_SendMessage()
{
    // 消息循环的处理在 IpcInSide_BroadcastSystemMessage 中
    UINT showMyAppMsg1 = RegisterWindowMessage(L"IpcInSide_SendMessage");
    UINT showMyAppMsg2 = RegisterWindowMessage(L"IpcInSide_PostMessage");
    SendMessage(HWND_BROADCAST, showMyAppMsg1, 0, 0);
    PostMessage(HWND_BROADCAST, showMyAppMsg2, 0, 0);
}