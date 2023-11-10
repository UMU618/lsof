#ifndef UNICODE
#define UNICODE
#endif

#include <stdio.h>
#include <tchar.h>

#include <windows.h>

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16

#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options);
typedef NTSTATUS(NTAPI* _NtQueryObject)(HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE,
* PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

PVOID GetNtProc(PCSTR ProcName) {
	return GetProcAddress(GetModuleHandle(L"ntdll.dll"), ProcName);
}

void ErrorExit(LPTSTR lpszFunction) {
	// Retrieve the system error message for the last-error code
	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf, 0, nullptr);

	_tprintf_s((LPTSTR)lpMsgBuf);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

void ShowErr() {
	CHAR errormsg[100];
	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, GetLastError(), 0,
		errormsg, sizeof(errormsg), nullptr);
	printf_s("ERROR: %s", errormsg);
}

int wmain(int argc, WCHAR* argv[]) {
	if (argc < 2) {
		printf_s("Usage: handles [pid]\n");
		return 1;
	}

	ULONG pid = _wtoi(argv[1]);
	HANDLE processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
	if (nullptr == processHandle) {
		printf_s("Could not open PID %d! (Don't try to open a system process.)\n",
			pid);
		return 1;
	}

	auto NtQuerySystemInformation =
		(_NtQuerySystemInformation)GetNtProc("NtQuerySystemInformation");
	auto NtDuplicateObject = (_NtDuplicateObject)GetNtProc("NtDuplicateObject");
	auto NtQueryObject = (_NtQueryObject)GetNtProc("NtQueryObject");

	ULONG handleInfoSize = 0x10000;
	PSYSTEM_HANDLE_INFORMATION handleInfo =
		(PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	// NtQuerySystemInformation won't give us the correct buffer size,
	//  so we guess by doubling the buffer size.
	NTSTATUS status;
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo,
		handleInfoSize, nullptr)) ==
		STATUS_INFO_LENGTH_MISMATCH) {
		handleInfo =
			(PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	}
	// NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
	if (!NT_SUCCESS(status)) {
		printf_s("NtQuerySystemInformation failed!\n");
		return 1;
	}

	for (ULONG i = 0; i < handleInfo->HandleCount; ++i) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		// Check if this handle belongs to the PID the user specified.
		if (handle.ProcessId != pid) {
			continue;
		}

		// Ignore EtwRegistration handles
		// https://bbs.kanxue.com/thread-207102-1.htm
		// UMU: Even WinDbg can't display this handle
		// !handle 0x4 0xf
		if (0x804 == handle.GrantedAccess) {
			printf_s("[%#x] EtwReqistration\n", handle.Handle);
			continue;
		}

		HANDLE dupHandle = nullptr;
		// Duplicate the handle so we can query it.
		status = NtDuplicateObject(processHandle, (void*)handle.Handle,
			GetCurrentProcess(), &dupHandle, 0, 0, 0);
		if (!NT_SUCCESS(status)) {
			printf_s("[%#x] !NtDuplicateObject #%#x!\n", handle.Handle, status);
			continue;
		}

		// Query the object type.
		auto objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		status = NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo,
			0x1000, nullptr);
		if (!NT_SUCCESS(status)) {
			printf_s("[%#x] !NtQueryObject #%#x!\n", handle.Handle, status);
			CloseHandle(dupHandle);
			continue;
		}

		// Query the object name (unless it has an access of
		//   0x0012019f, on which NtQueryObject could hang.
		// UMU: You can use brower to navigate file://.//pipe//
		if (0x0012019f == handle.GrantedAccess) {
			// We have the type, so display that.
			printf_s("[%#x] %.*S: (did not get pipe name)\n", handle.Handle,
				objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer);

			free(objectTypeInfo);
			CloseHandle(dupHandle);
			continue;
		}

		PVOID objectNameInfo = malloc(0x1000);
		ULONG returnLength;
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation,
			objectNameInfo, 0x1000, &returnLength))) {
			// Reallocate the buffer and try again.
			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation,
				objectNameInfo, returnLength, nullptr))) {
				// We have the type name, so just display that.
				printf_s("[%#x] %.*S: (could not get name)\n", handle.Handle,
					objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer);

				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				continue;
			}
		}

		// Cast our buffer into an UNICODE_STRING.
		UNICODE_STRING objectName = *(PUNICODE_STRING)objectNameInfo;

		// Print the information!
		if (objectName.Length) {
			// The object has a name.
			printf_s("[%#x] %.*S: %.*S\n", handle.Handle,
				objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer,
				objectName.Length / 2, objectName.Buffer);
		}
		else {
			// Print something else.
			printf_s("[%#x] %.*S: (unnamed)\n", handle.Handle,
				objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer);
		}

		free(objectTypeInfo);
		free(objectNameInfo);
		CloseHandle(dupHandle);
	}

	free(handleInfo);
	CloseHandle(processHandle);

	return 0;
}