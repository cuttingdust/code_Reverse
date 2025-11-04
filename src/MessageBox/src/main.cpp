#include <iostream>

#include <windows.h>

int DisplayResourceNAMessageBox()
{
    int msgboxID = MessageBox(NULL, (LPCWSTR)L"Resource not available\nDo you want to try again?",
                              (LPCWSTR)L"Account Details", MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2);

    switch (msgboxID)
    {
        case IDCANCEL:
            // TODO: add code
            break;
        case IDTRYAGAIN:
            // TODO: add code
            break;
        case IDCONTINUE:
            // TODO: add code
            break;
    }

    return msgboxID;
}

int main(int argc, char *argv[])
{
    // int WINAPI MessageBox(HWND    hWnd,      /// 窗口句柄
    //                       LPCTSTR lpText,    /// 字符串 描述
    //                       LPCTSTR lpCaption, /// 字符串 标题
    //                       UINT    uType      /// 窗口类型
    // );

    MessageBoxA(0, "我第一次调用API", "标题123", MB_OK);

    printf("dddd\n");

    MessageBoxA(0, "我的内容adsf132", "标d题", MB_OKCANCEL | MB_ICONINFORMATION); /// 弹出一个 带有确定按钮的 窗口

    /// MB_DEFBUTTON3 第三个按钮是默认按钮
    MessageBoxA(0, "fdsaf我的内容132xxx", "标题ddd", MB_USERICON | MB_ABORTRETRYIGNORE | MB_DEFBUTTON3);

    MessageBoxA(0, "fdsaf我的内容132xxx", "标题ddd", MB_ICONERROR | MB_CANCELTRYCONTINUE | MB_DEFBUTTON1);

    DisplayResourceNAMessageBox();

    return 0;
}
