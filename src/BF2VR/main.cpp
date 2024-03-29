// Copyright Ethan Porcaro

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#include <iostream>
#include <Windows.h>
#include "Logging.h"

#include "BF2Service.h"
#include "D3DService.h"
#include "OpenXRService.h"
#include "ActionsService.h"

namespace BF2VR {

    void logo() {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole,
            FOREGROUND_BLUE | FOREGROUND_INTENSITY);

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

        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
    }

    void Shutdown(int setupLevel, HMODULE hModule) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole,
            FOREGROUND_BLUE | FOREGROUND_GREEN);

        Logging::Log("[CORE] Unloading BF2VR...");

        if (setupLevel >= 3) {
            Logging::Log("[D3D11] Unhooking D3D11...");
            D3DService::Uninitialize();
        }

        if (setupLevel >= 2) {
            Logging::Log("[OPENXR] Unloading OpenXR...");
            OpenXRService::Uninitialize();
        }

        if (setupLevel >= 1) {
            Logging::Log("[BF2] Unhooking BF2Service..");
            BF2Service::Uninitialize();
        }

        Logging::Log("[CORE] BF2VR unloaded, You may now close this window");
        FreeConsole();
        FreeLibraryAndExitThread(hModule, 0);
    }

    void FinalizeAsIs(int setupLevel, HMODULE hModule) {
        Logging::Log("[CORE] Loaded. Press END to unload BF2VR");

        HWND ownWindow = FindWindowA("Frostbite", "STAR WARS Battlefront II");
        if (ownWindow) {
            SetForegroundWindow(ownWindow);
            SetActiveWindow(ownWindow);
            RECT rect;
            GetWindowRect(ownWindow, &rect);
            SetWindowPos(ownWindow, 0, 0, 0, rect.right - 1, rect.bottom, 0);
            SetWindowPos(ownWindow, 0, 0, 0, rect.right + 1, rect.bottom, 0);
        } else {
            Logging::Log("[CORE] Unable to bring window to front. Click the window to get motion controls.");
        }

        while (true) {
            if (GetAsyncKeyState(VK_END)) {
                break;
            }
        }

        RECT rect;
        if (ownWindow) {
            GetWindowRect(ownWindow, &rect);
            SetWindowPos(ownWindow, 0, 0, 0, rect.right - 1, rect.bottom, 0);
            SetWindowPos(ownWindow, 0, 0, 0, rect.right + 1, rect.bottom, 0);
        }
        Shutdown(setupLevel, hModule);
    }

    DWORD __stdcall MainThread(HMODULE hModule) {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        logo();
        Logging::Log("[CORE] BF2VR injected");

        // Add crash handler
        SetUnhandledExceptionFilter(Logging::UnhandledHandler);

        int setupLevel = 0;

        Logging::Log("[D3D11] Capturing DirectX resources...");
        if (D3DService::CaptureResources() != 0) {
            Logging::Log("[D3D11] Could not get D3D11 resources");
            Shutdown(setupLevel, hModule);
        }

        Logging::Log("[BF2] Initializing BF2Service...");
        if (BF2Service::Initialize() != 0) {
            Shutdown(setupLevel, hModule);
        }
        setupLevel++;

        Logging::Log("[OPENXR] Loading OpenXR...");
        if (OpenXRService::Initialize() != 0) {
            Shutdown(setupLevel, hModule);
        }
        setupLevel++;

        Logging::Log("[OPENXR] Loading Actions...");
        if (ActionsService::Initialize() != 0) {
            Shutdown(setupLevel, hModule);
        }

        Logging::Log("[D3D11] Hooking DirectX...");
        if (D3DService::Initialize() != 0) {
            Shutdown(setupLevel, hModule);
        }
        setupLevel++;

        FinalizeAsIs(setupLevel, hModule);
        return 0;
    }

}  // namespace BF2VR


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)BF2VR::MainThread, hModule, 0, nullptr);
    }
    return TRUE;
}
