#include "md5.hpp"
#include <Windows.h>
#include<chrono>
#include <filesystem>
#include <TlHelp32.h>
#include <Psapi.h>
#include <tchar.h>
#include <stdlib.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <wow64apiset.h>

#pragma comment (lib, "wintrust")
#pragma comment (lib, "psapi.lib")

namespace MEMORY {
	HANDLE Attach(const wchar_t* ProcessName, DWORD ProcAccessRights) {

        // function pasted from my Multithread-base, cba, quick and dirty

		HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		HANDLE ProcessHandle = NULL;

		if (Snapshot)
		{
			PROCESSENTRY32 pe;
			pe.dwSize = sizeof(PROCESSENTRY32);


			if (Process32First(Snapshot, &pe))
			{
				do
				{
					if (!wcscmp(pe.szExeFile, ProcessName))
					{
						ProcessHandle = OpenProcess(ProcAccessRights, false, pe.th32ProcessID);
					}
				} while (Process32Next(Snapshot, &pe));
			}
			CloseHandle(Snapshot);
		}

        // invalid handles went brrr few years ago
		printf("ProcessHandle(%s): 0x%x\n", ProcessName, (DWORD)ProcessHandle);

		if (ProcessHandle)
		{
			return ProcessHandle;
		}
		else
		{
			return 0;
		}

	}

    // wrapper for cleanliness
	bool Detach(HANDLE Handle) {
		CloseHandle(Handle);
		printf_s("[+] Closed handle to selected file/process");
		return true;
	}

    std::string GetFilePathFromHandle(DWORD PID) {
        HANDLE ProcessHandle;
        wchar_t Path[MAX_PATH];

        ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID); // QUERY_INFO | READ probably, this shit ain't lookin' too legit with ALL_ACCESS
        if (ProcessHandle != NULL) {
            if (GetModuleFileNameEx(ProcessHandle, NULL, Path, MAX_PATH)) {
                CloseHandle(ProcessHandle);
                std::wstring WString(Path);
                std::string szPath(WString.begin(), WString.end());
                std::filesystem::path bValidPath = szPath;
                std::ifstream test(bValidPath);
                if (!test)
                    return "";
                else {
                    //std::wcout << "\"" << Path << "\""             -- stupid piece of shit, after 236 times debugging you are commented out
                    return szPath;
                }
            }
            else {
                CloseHandle(ProcessHandle);
                return "";
            }
        }
        else {
            if(ProcessHandle)
                CloseHandle(ProcessHandle);
            return "";
        }
    }

    BOOL VerifyEmbeddedSignature(const wchar_t* pwszSourceFile) // function from WinTrustVerify, slightly modified
    {
        LONG lStatus;
        DWORD dwLastError;


        WINTRUST_FILE_INFO FileData;
        memset(&FileData, 0, sizeof(FileData));
        FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
        FileData.pcwszFilePath = pwszSourceFile;
        FileData.hFile = NULL;
        FileData.pgKnownSubject = NULL;

        GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA WinTrustData;

        memset(&WinTrustData, 0, sizeof(WinTrustData));

        WinTrustData.cbStruct = sizeof(WinTrustData);
        WinTrustData.pPolicyCallbackData = NULL;
        WinTrustData.pSIPClientData = NULL;
        WinTrustData.dwUIChoice = WTD_UI_NONE;
        WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        WinTrustData.hWVTStateData = NULL;
        WinTrustData.pwszURLReference = NULL;
        WinTrustData.dwUIContext = 0;
        WinTrustData.pFile = &FileData;

        lStatus = WinVerifyTrust( NULL, &WVTPolicyGUID, &WinTrustData);

        switch (lStatus)
        {
        case ERROR_SUCCESS:
            //wprintf_s(L"[WVT] The file \"%s\" is signed and the signature was verified. - ",pwszSourceFile);   -- debug
            return true;
            break;

        case TRUST_E_NOSIGNATURE:
            dwLastError = GetLastError();
            if (TRUST_E_NOSIGNATURE == dwLastError || TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError || TRUST_E_PROVIDER_UNKNOWN == dwLastError)
            {
                //wprintf_s(L"[WVT] The file \"%s\" is not signed. - ", pwszSourceFile); -- debug
                return false;
            }
            else
            {
                //wprintf_s(L"[WVT] An unknown error occurred trying to verify the signature of the \"%s\" file. - ", pwszSourceFile); -- debug
                return false;
            }

            break;
        default:
            wprintf_s(L"[WVT] Error is: 0x%x - ", lStatus);
            break;
        }

        WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

        lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

        return true;
    }

	void IterateAllProcesses(bool LogSigned = false, bool LogUnsigned = false, bool LogAll = true) {

		HANDLE ProcessSnapshot;
		PROCESSENTRY32 ProcEntry;

        // "default" process iterating, no comments needed

		ProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (ProcessSnapshot == INVALID_HANDLE_VALUE)
			printf_s("[-] CreateToolHelp32Snapshot == INVALID_HANDLE_VALUE\n");

		ProcEntry.dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(ProcessSnapshot, &ProcEntry))   
			printf_s("[-] Process32First failed\n");

		printf_s("\n\nListing all processes currently running:\n\n");

		do {

			if (!ProcEntry.th32ProcessID || !ProcEntry.szExeFile)
				continue;

            PVOID OldValue = NULL;

            if (!IsWow64Process) { // i got terminal cancer when running this in x86. why does it redirect the FS to x86 locations and just show up empty? this is why, right under this.
                if (Wow64DisableWow64FsRedirection(&OldValue)) // disable redirections
                {
                    std::string szFPFH = MEMORY::GetFilePathFromHandle(ProcEntry.th32ProcessID);
                    std::wstring wszConv = std::wstring(szFPFH.begin(), szFPFH.end());
                    const wchar_t* FPFH = wszConv.c_str();
                    //FPFH = MEMORY::GetFilePathFromHandle(ProcEntry.th32ProcessID);
                    if (FPFH != NULL) {
                        std::ifstream test(FPFH);
                        if (!test)
                            std::wcout << "[WVT] Failed to get path (SYS) - " <<  " PID: " << ProcEntry.th32ProcessID << "\t" << " Name: " << ProcEntry.szExeFile << "\t" << std::endl;
                        else
                        {
                            if (!MEMORY::VerifyEmbeddedSignature(FPFH)) {
                                std::string szHash = MD5::CalculateHash(szFPFH);
                                wszConv = std::wstring(szHash.begin(), szHash.end());
                                std::wcout << "[WVT] Unsigned/exploitable/whitelisted executable - "  << "Hash: " << wszConv /* rename it to hash, i am too lazy*/ << " PID: " << ProcEntry.th32ProcessID << "\t" << " Name: " << ProcEntry.szExeFile << "\t" << std::endl;
                            }
                                
                        } 

                        if (FALSE == Wow64RevertWow64FsRedirection(OldValue)) // enable them, if it shits itself, we have a brilliant error that still gives you more info than the government
                        {
                            printf_s("WOW64 took a large shit \n"); 
                            continue;
                        }
                    }
                }
            }
            else {
                std::string szFPFH = MEMORY::GetFilePathFromHandle(ProcEntry.th32ProcessID); // return proper path as string
                std::wstring wszConv = std::wstring(szFPFH.begin(), szFPFH.end()); // convert to wstring and wchar_t under
                const wchar_t* FPFH = wszConv.c_str();
                if (FPFH != NULL) { // checks
                    std::ifstream test(FPFH);
                    if (!test) // check if path is valid
                        std::wcout << "[WVT] Failed to get path (SYS) - " << " PID: " << ProcEntry.th32ProcessID << "\t" << " Name: " << ProcEntry.szExeFile << "\t" << std::endl;
                    else {
                        if (!MEMORY::VerifyEmbeddedSignature(FPFH)) { // if path is valid, check for signatures
                            std::string szHash = MD5::CalculateHash(szFPFH); // calculate unsigned whitelisted file hash
                            wszConv = std::wstring(szHash.begin(), szHash.end()); // convert it for wcout, picky whore
                            std::wcout << "[WVT] Unsigned/exploitable/whitelisted executable - " << "Hash: " << wszConv /* rename it to hash, i am too lazy*/ << " PID: " << ProcEntry.th32ProcessID << "\t" << " Name: " << ProcEntry.szExeFile << "\t" << std::endl;
                        }
                    }
                }
                else {
                    // std::wcout << "[WVT] FPFH == NULL " << "\n\t" << "PID: " << ProcEntry.th32ProcessID << "\t\t" << " Name: " << ProcEntry.szExeFile << "\t\n" << std::endl;  -- no need for this anymore
                    continue;
                }
            }
		}
		while (Process32Next(ProcessSnapshot, &ProcEntry));

        
	}

	// these functions are left here for grabbing a handle to the process, afterwards using EnumProcessModules and grabbing the path to the process and 
	// providing it further to Calculate/Change MD5 hash. WIP
    // UPD: they are needed finally, a whole day after :D

}
