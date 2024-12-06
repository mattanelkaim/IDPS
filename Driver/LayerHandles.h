#pragma once

// Check if compiling for kernel mode
#ifdef _KERNEL_MODE
#include <ntdef.h> // For kernel-mode drivers

typedef struct _KERNEL_OBJECTS
{
	PVOID ethernet, internet, transport, application;
} KERNEL_OBJECTS, *PKERNEL_OBJECTS;

#else
#include <windows.h> // For user-mode applications
#endif

typedef struct _HANDLES
{
	HANDLE ethernet, internet, transport, application;
} HANDLES, *PHANDLES;