#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <atlstr.h>


namespace MD5 {

    std::string GetDir(std::string Process = "") {

        char CurrentPath[MAX_PATH];
        std::string FullPath;
        LPWSTR CurrentPathW = CA2CT(CurrentPath);
        if (Process == "") {
            if (GetModuleFileName(NULL, CurrentPathW, MAX_PATH) == 0) {
                printf_s("[-] GetModuleFileName == NULL \n");
                return "";
            }
            FullPath = CurrentPath;
        }
        else
        {
            FullPath = Process;
        }

        size_t LastSlashPos = FullPath.find_last_of("\\");

        if (LastSlashPos != std::string::npos) {
            return FullPath.substr(0, LastSlashPos + 1);
        }
        else {
            printf_s("[-] GetFullPath == NULL \n");
            return "";
        }
    }

    std::vector<char> PatternGen() {
        std::vector<char> pattern;

        for (char ch = 'A'; ch <= 'D'; ++ch) {
            pattern.push_back(ch);
        }

        return pattern;
    }


    std::string CalculateHash(const std::string& FilePath) {
        std::ifstream File(FilePath, std::ios::binary);
        if (!File.is_open()) {
            return "";
        }

        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ||
            !CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            return "";
        }

        const int BufferSize = 4096;
        std::vector<BYTE> Buffer(BufferSize);
        DWORD BytesRead = 0;

        while (File.read(reinterpret_cast<char*>(Buffer.data()), Buffer.size()) && File.gcount() > 0) {
            BytesRead = static_cast<DWORD>(File.gcount());

            if (!CryptHashData(hHash, Buffer.data(), BytesRead, 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return "";
            }
        }

        BYTE Hash[16];
        DWORD HashSize = 16;

        if (!CryptGetHashParam(hHash, HP_HASHVAL, Hash, &HashSize, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        std::stringstream SSObj;

        for (int i = 0; i < HashSize; ++i) {
            SSObj << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(Hash[i]);
        }

        return SSObj.str();
    }

    bool ChangeHash(std::string Process = "") {
        std::string ExeDir = GetDir(Process);
        if (ExeDir.empty()) {
            return false;
        }

        char CurrentPath[MAX_PATH];
        LPWSTR CurrentPathW = CA2CT(CurrentPath);
        // HANDLE Target = MEMORY::Attach(Process.c_str(), 0);     -- from test build


        std::string oFile;
        std::string mFile;

        if (Process != "") {
            oFile = Process;
        }
        else {
            if (GetModuleFileName(NULL, CurrentPathW, MAX_PATH) == 0) {
                printf_s("[-] GetModuleFileName == NULL \n");
                return false;
            }
            oFile = CurrentPath;
        }
        
        mFile = ExeDir + "md5less.exe";

        std::ifstream File(oFile, std::ios::binary);
        if (!File.is_open()) {
            printf_s("[-] oFile == NULL \n");
            return false;
        }

        std::string oHash = MD5::CalculateHash(oFile);
        if (oHash.empty()) {
            printf_s("[-] CalculateHash failed. (hash string empty) \n");
            return false;
        }

        printf_s(("[+] CalculateHash(oFile) resulted " + oHash + " \n").c_str());

        std::vector<char> FileData((std::istreambuf_iterator<char>(File)), std::istreambuf_iterator<char>());

        PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(FileData.data());
        if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            printf_s("[-] PIMAGE_DOS_HEADER invalid (!= DOS_SIGNATURE) \n");
            return false;
        }

        PIMAGE_NT_HEADERS NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(&FileData[DosHeader->e_lfanew]);
        if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
            printf_s("[-] PIMAGE_NT_HEADERS invalid (!= NT_SIGNATURE) \n");
            return false;
        }

        PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
        PIMAGE_SECTION_HEADER CodeSection = nullptr;
        for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i) {
            if (strcmp(reinterpret_cast<char*>(SectionHeader[i].Name), ".text") == 0) {
                CodeSection = &SectionHeader[i];
                break;
            }
        }

        if (!CodeSection) {
            printf_s("[-] .text not valid \n");
            return false;
        }

        std::vector<char> PatternToFind = PatternGen();

        if (CodeSection->PointerToRawData >= FileData.size()) {
            printf_s("[-] .text offset not valid \n");
            return false;
        }

        auto CodeStart = FileData.begin() + CodeSection->PointerToRawData;
        auto CodeEnd = CodeStart + CodeSection->SizeOfRawData;

        if (CodeEnd > FileData.end()) {
            printf_s("[-] .text code section size invalid \n");
            return false;
        }

        std::vector<char>::iterator Iter = std::search(CodeStart, CodeEnd, PatternToFind.begin(), PatternToFind.end());

        std::streamoff Offset = std::distance(FileData.begin(), Iter);

        FileData[Offset] = 0x12;

        std::ofstream OutFile(mFile, std::ios::binary);
        if (!OutFile.is_open()) {
            printf_s("[-] mFile == NULL \n");
            return false;
        }

        OutFile.write(FileData.data(), FileData.size());
        OutFile.close();

        std::string mHash = MD5::CalculateHash(mFile);
        if (!mHash.empty()) {
            printf_s(("[+] CalculateHash(mFile) resulted " + mHash +" \n\n").c_str());
            printf_s("[=] Successfully generated random hash and created a modified executable.\n");
            printf_s("    Press any key to continue...");
            return true;
        }
        else {
            printf_s("[-] CalculateHash failed (hash string empty) \n");
            return false;
        }

        return true;
    }


}

