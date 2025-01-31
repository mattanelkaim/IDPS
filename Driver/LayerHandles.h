#pragma once

// Check if compiling for kernel mode
#ifdef _KERNEL_MODE
#include <ntdef.h> // For kernel-mode drivers

#define BASE_MUTEX_DIRECTORY L"\\BaseNamedObjects\\"
#define BASE_FILE_DIRECTORY L"\\??\\C:\\IDPS_shared_files\\"

typedef struct _KERNEL_OBJECTS
{
	PVOID ethernet, internet, transport, application;
} KERNEL_OBJECTS, *PKERNEL_OBJECTS;

#else // !_KERNEL_MODE

#include <windows.h> // For user-mode applications
#include <winioctl.h>

#define BASE_MUTEX_DIRECTORY L"Global\\"
#define BASE_FILE_DIRECTORY L"C:\\IDPS_shared_files\\"

#endif // !_KERNEL_MODE

typedef struct _IOCTL_HANDLES
{
	unsigned long pid;
	HANDLE mutex;
} IOCTL_HANDLES, *PIOCTL_HANDLES;

#define PACKET_MUTEX_PATH (BASE_MUTEX_DIRECTORY L"packetMutex")
#define PACKET_FILE_PATH (BASE_FILE_DIRECTORY L"packetFlow.bin")

#define IOCTL_SEND_HANDLES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SEND_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRUNCATE_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)