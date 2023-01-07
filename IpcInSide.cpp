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

    // Ϊ�˷�������ֻ����һ�Σ�����˾� break
    std::string str_recv, str_send;
    while(1)
    {
        Sleep(1000);

        //�ӿͻ��˽�����Ϣ��������
        if (ReadFile(*pHandle, inBuffer, 1024, &ReadNum, NULL) == FALSE) { printf("��ȡ����ʧ�ܣ������ѶϿ�... ErrorCode = %d \n", GetLastError()); break; }
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

    // ֻ�е�һ�������Ľ�����Ϊ����ˣ�����ĳ��Զ���ʧ��
	hPipe = CreateNamedPipe(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE, 1, 0, 0, 1000, NULL);
	if (hPipe == INVALID_HANDLE_VALUE)
		return false;

    spdlog::info("[IpcInSide_CreateNamedPipe] ProcCount:{} ", 1);

    CreateThread(0, 0, ThreadProc, &hPipe, 0, 0);
    

    return true;
}
void IpcInSide_CreateNamedPipe()
{
    // �ο����룺https://www.codenong.com/cs106911135/

    if (!CreateNamedPipe_Server())
    {
        // ���Ƿ���˾�ִ�пͻ����߼�
        char outBuffer[1024] = { 0 };  
        char inBuffer[1024] = { 0 };   
        DWORD WriteNum = 0;
        DWORD ReadNum = 0;

        if (WaitNamedPipe(PIPE_NAME, NMPWAIT_WAIT_FOREVER) == FALSE)
            return;

        HANDLE hPipe = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hPipe == INVALID_HANDLE_VALUE)
            return;

        //�����˷�����Ϣ
        strcpy(outBuffer, "count");
        if (WriteFile(hPipe, outBuffer, (DWORD)strlen(outBuffer), &WriteNum, NULL) == FALSE) { printf("��������ʧ�ܣ�\n"); }

        //�ӷ���˽�����Ϣ
        if (ReadFile(hPipe, inBuffer, 1024, &ReadNum, NULL) == FALSE) { printf("��������ʧ�ܣ�\n");  }
        
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

    // �������Գ�ʼ��
    HINSTANCE hIns = GetModuleHandle(0);
    WNDCLASSEX wc;
    wc.cbSize = sizeof(wc);								// ����ṹ��С
    wc.style = CS_HREDRAW | CS_VREDRAW;					// ����ı��˿ͻ�����Ŀ�Ȼ�߶ȣ������»����������� 
    wc.cbClsExtra = 0;									// ���ڽṹ�ĸ����ֽ���
    wc.cbWndExtra = 0;									// ����ʵ���ĸ����ֽ���
    wc.hInstance = hIns;								// ��ģ���ʵ�����
    wc.hIcon = NULL;									// ͼ��ľ��
    wc.hIconSm = NULL;									// �ʹ����������Сͼ��ľ��
    wc.hbrBackground = (HBRUSH)COLOR_WINDOW;			// ������ˢ�ľ��
    wc.hCursor = NULL;									// ���ľ��
    wc.lpfnWndProc = __WndProc;							// ���ڴ�������ָ��
    wc.lpszMenuName = NULL;								// ָ��˵���ָ��
    wc.lpszClassName = L"LYSM_class";					// ָ�������Ƶ�ָ��

    // Ϊ����ע��һ��������
    if (!RegisterClassEx(&wc)) {
        return 0;
    }

        // ��������
        HWND hWnd = CreateWindowEx(
            WS_EX_TOPMOST,				// ������չ��ʽ����������
            L"LYSM_class",				// ��������
            L"LYSM_title",				// ���ڱ���
            WS_OVERLAPPEDWINDOW,		// ������ʽ���ص�����
            0,							// ���ڳ�ʼx����
            0,							// ���ڳ�ʼy����
            800,						// ���ڿ��
            600,						// ���ڸ߶�
            0,							// �����ھ��
            0,							// �˵���� 
            hIns,						// �봰�ڹ�����ģ��ʵ���ľ��
            0							// �������ݸ�����WM_CREATE��Ϣ
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
    // BroadcastSystemMessageEx ͬ��

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
    // ��Ϣѭ���Ĵ����� IpcInSide_BroadcastSystemMessage ��
    UINT showMyAppMsg1 = RegisterWindowMessage(L"IpcInSide_SendMessage");
    UINT showMyAppMsg2 = RegisterWindowMessage(L"IpcInSide_PostMessage");
    SendMessage(HWND_BROADCAST, showMyAppMsg1, 0, 0);
    PostMessage(HWND_BROADCAST, showMyAppMsg2, 0, 0);
}