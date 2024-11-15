//#define _AMD64_
#include <ntddk.h>
#include <ndis.h>

// IOCTL code for user-mode communication
#define IOCTL_READ_RAW_PACKET CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

// Device extension structure
typedef struct _DEVICE_EXTENSION {
    NDIS_HANDLE NdisHandle;
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;

// Function declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// Entry point
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\RawPacketDriver");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\RawPacketDriver");
    PDEVICE_OBJECT deviceObject;
    NTSTATUS status;

    // Create the device
    status = IoCreateDevice(
        DriverObject,
        sizeof(DEVICE_EXTENSION),
        &deviceName,
        FILE_DEVICE_NETWORK,
        0,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Create the symbolic link
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Set up the driver object
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}

// Unload routine
void DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\RawPacketDriver");
    IoDeleteSymbolicLink(&symbolicLink);
    IoDeleteDevice(DriverObject->DeviceObject);
}

// Create/Close routine
NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Device control routine
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_READ_RAW_PACKET: {
        // Simulated packet read for demonstration purposes
        UCHAR dummyPacket[128] = { /* Simulated packet data */ };
        size_t packetSize = sizeof(dummyPacket);

        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < packetSize) {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, dummyPacket, packetSize);
            Irp->IoStatus.Information = packetSize;
            status = STATUS_SUCCESS;
        }
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
