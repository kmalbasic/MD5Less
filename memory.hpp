#include <Windows.h>
#include<chrono>
#include <TlHelp32.h>

namespace MEMORY {
	HANDLE Attach(const char* ProcessName, DWORD ProcAccessRights) {

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
					if (!strcmp(pe.szExeFile, ProcessName))
					{
						ProcessHandle = OpenProcess(ProcAccessRights, false, pe.th32ProcessID);
					}
				} while (Process32Next(Snapshot, &pe));
			}
			CloseHandle(Snapshot);
		}

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

	bool Detach(HANDLE Handle) {
		CloseHandle(Handle);
		printf_s("[+] Closed handle to selected file/process");
		return true;
	}


	// these functions are left here for grabbing a handle to the process, afterwards using EnumProcessModules and grabbing the path to the process and 
	// providing it further to Calculate/Change MD5 hash. WIP

}
