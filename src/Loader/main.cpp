// Copyright Ethan Porcaro

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#include <Windows.h>
#include <TlHelp32.h>
#include <direct.h>
#include <ShlObj_core.h>
#include <iostream>

DWORD PIDFromName(const char* processName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 1;
    }
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return 1;
    } do {
        if (strcmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hProcessSnap);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return 0;
}

int injectDLL(DWORD pid, const char* dllPath) {
    HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (proc_handle == INVALID_HANDLE_VALUE) {
        return 1;
    }
    void* loc = VirtualAllocEx(proc_handle, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BOOL WPM = WriteProcessMemory(proc_handle, loc, dllPath, strlen(dllPath) + 1, nullptr);
    if (!WPM) {
        CloseHandle(proc_handle);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(proc_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, nullptr);
    if (!hThread) {
        VirtualFree(loc, strlen(dllPath) + 1, MEM_RELEASE);
        CloseHandle(proc_handle);
        return 1;
    }

    CloseHandle(proc_handle);
    VirtualFree(loc, strlen(dllPath) + 1, MEM_RELEASE);
    CloseHandle(hThread);
    return 0;
}

void hang() {
    std::cout << "Press any key to exit..." << std::endl;
    // Wait for user input.
    getchar();
}

void logo() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);

    std::cout << R""""(
$$$$$$$\  $$$$$$$$\  $$$$$$\  $$\    $$\ $$$$$$$\
$$  __$$\ $$  _____|$$  __$$\ $$ |   $$ |$$  __$$\
$$ |  $$ |$$ |      \__/  $$ |$$ |   $$ |$$ |  $$ |
$$$$$$$\ |$$$$$\     $$$$$$  |\$$\  $$  |$$$$$$$  |
$$  __$$\ $$  __|   $$  ____/  \$$\$$  / $$  __$$<
$$ |  $$ |$$ |      $$ |        \$$$  /  $$ |  $$ |
$$$$$$$  |$$ |      $$$$$$$$\    \$  /   $$ |  $$ |
\_______/ \__|      \________|    \_/    \__|  \__|
)"""";

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

int main() {
    logo();

    // Create folder for logging
    CHAR my_documents[MAX_PATH];
    HRESULT result = SHGetFolderPath(nullptr, CSIDL_PERSONAL, nullptr, SHGFP_TYPE_CURRENT, my_documents);
    if (result != S_OK) {
        std::cout << "[BF2VR] Failed to get My Documents folder path for crash logs" << std::endl;
        hang();
        return 1;
    }

    if (_mkdir((std::string(my_documents) + "\\BF2VR").c_str()) != 0) {
        if (errno != EEXIST) {
            std::cout << "[BF2VR] Failed to create BF2VR folder in My Documents for crash logs" << std::endl;
            hang();
            return 1;
        }
    }

    std::cout << "Waiting for Battlefront II to start...";
    while (!FindWindowA("Frostbite", "STAR WARS Battlefront II")) {
        Sleep(500);
        std::cout << ".";
    }

    DWORD pid = PIDFromName("starwarsbattlefrontii.exe");

    // Ensure the DLL is in the right place.
    if (GetFileAttributes("BF2VR.dll") == INVALID_FILE_ATTRIBUTES) {
        std::cout << "BF2VR.dll is not in the same directory as this loader" << std::endl;
        hang();
        return 1;
    }

    // Get the path to the DLL.
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/");
    std::string cwd = std::string(buffer).substr(0, pos);
    std::string modpath = cwd + "\\BF2VR.dll";
    // Inject the DLL.

    if (injectDLL(pid, modpath.c_str())) {
        std::cout << "Failed to inject BF2VR.dll" << std::endl;
        hang();
        return 1;
    }

    std::cout << "Injected BF2VR.dll into Battlefront II" << std::endl;
    std::cout << "PID: " << pid << std::endl;
    Sleep(5000);
    return 0;
}
