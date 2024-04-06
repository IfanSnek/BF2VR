// Copyright Ethan Porcaro

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#include "Logging.h"
#include <ShlObj.h>
#include <Dbghelp.h>
#include <iostream>
#include <chrono>

namespace BF2VR {
    void Logging::Log(const std::string& message, int code) {
        // If the log file is not open, open it.
        if (!logFile.is_open()) {
            CHAR my_documents[MAX_PATH];
            HRESULT result = SHGetFolderPath(nullptr, CSIDL_PERSONAL, nullptr, SHGFP_TYPE_CURRENT, my_documents);
            if (result != S_OK) {
                std::cout << "[BF2VR] Failed to get My Documents folder path for logging" << std::endl;
                return;
            }

            logFile.open(std::string(my_documents) + "\\BF2VR\\BF2VR.txt", std::ios::out | std::ios::app);
            auto timestamp = std::chrono::system_clock::now();
            auto timestamp_t = std::chrono::system_clock::to_time_t(timestamp);
            logFile << std::endl << "New BF2VR log created on " << std::ctime(&timestamp_t) << std::endl;
        }

        if (code != -99) {
            std::cout << "[BF2VR] " << message << " (code " << code << ")" << std::endl;
            logFile << "[BF2VR] " << message << " (code " << code << ")" << std::endl;
        } else {
            std::cout << "[BF2VR] " << message << std::endl;
            logFile << "[BF2VR] " << message << std::endl;
        }
    }

    void Logging::MakeMinidump(EXCEPTION_POINTERS* e) {
        auto hDbgHelp = LoadLibraryA("dbghelp");
        if (hDbgHelp == nullptr) {
            return;
        }
        auto pMiniDumpWriteDump = (decltype(&MiniDumpWriteDump))GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
        if (pMiniDumpWriteDump == nullptr) {
            return;
        }

        CHAR my_documents[MAX_PATH];
        HRESULT result = SHGetFolderPath(nullptr, CSIDL_PERSONAL, nullptr, SHGFP_TYPE_CURRENT, my_documents);
        if (result != S_OK) {
            std::cout << "[BF2VR] Failed to get My Documents folder path for crash logs" << std::endl;
            return;
        }

        std::time_t t = std::time(nullptr);
        std::tm tmInfo;
        localtime_s(&tmInfo, &t);

        CHAR formattedTime[MAX_PATH];
        std::strftime(formattedTime, sizeof(formattedTime), "%Y-%m-%d_%H-%M-%S", &tmInfo);

        std::string crashDumpFilePath = std::string(my_documents) + "\\BF2VR\\CrashDump_" + formattedTime + ".dmp";
        std::cout << "Opening crash dump file: " << crashDumpFilePath << std::endl;


        auto hFile = CreateFileA(crashDumpFilePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::cout << "[BF2VR] Failed to write crash log to file" << std::endl;
            return;
        }


        MINIDUMP_EXCEPTION_INFORMATION exceptionInfo;
        exceptionInfo.ThreadId = GetCurrentThreadId();
        exceptionInfo.ExceptionPointers = e;
        exceptionInfo.ClientPointers = FALSE;

        auto dumped = pMiniDumpWriteDump(
            GetCurrentProcess(),
            GetCurrentProcessId(),
            hFile,
            MINIDUMP_TYPE(MiniDumpWithIndirectlyReferencedMemory | MiniDumpScanMemory),
            e ? &exceptionInfo : nullptr,
            nullptr,
            nullptr);

        CloseHandle(hFile);

        MessageBox(nullptr, TEXT("BF2VR Crashed. There is a crash dump in the Documents/BF2VR/ folder. The program will now exit."), TEXT("BF2VR"), MB_OK | MB_TOPMOST);

        return;
    }

    LONG WINAPI Logging::UnhandledHandler(EXCEPTION_POINTERS* e) {
        MakeMinidump(e);
        return EXCEPTION_CONTINUE_SEARCH;
    }
}  // namespace BF2VR
