#include <ndis.h>
#include <ntddk.h>
#include <stdio.h> // sprintf()

// These cannot be const nor constexpr!
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\IDPS Sniffer Device");
UNICODE_STRING SYMLINK_NAME = RTL_CONSTANT_STRING(L"\\??\\SnifferDeviceLink");

// IOCTL code for user-mode communication
#define IOCTL_READ_RAW_PACKET CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

// Function declarations
extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" DRIVER_UNLOAD DriverUnload;
//extern "C" NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
extern "C" NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

extern "C" NTSTATUS DriverPassThru([[maybe_unused]] PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    switch (irpSp->MajorFunction)
    {
    case IRP_MJ_CREATE:
        KdPrint(("Create request!\n"));
        break;
    case IRP_MJ_CLOSE:
        KdPrint(("Close request!\n"));
        break;
    case IRP_MJ_READ:
        KdPrint(("Read request!\n"));
        break;
    default:
        break;
    }

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Entry point
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, [[maybe_unused]] PUNICODE_STRING RegistryPath)
{
    KdPrint(("Entry!\n"));
    NTSTATUS status; // Re-used to check each API function

    PDEVICE_OBJECT deviceObject;

    // Create the device                                                   TODO: IS TYPE CORRECT??
    status = IoCreateDevice(DriverObject, 0, &DEVICE_NAME, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status))
    {
        // Print error with status code
        if (status == STATUS_OBJECT_NAME_COLLISION)
            KdPrint(("FAILED to create device: NAME_COLLISION\n"));
        else
        {
            KdPrint(("FAILED to create device:\n"));
            char num_str[sizeof(LONG) + 2] = {0};
            sprintf(num_str, "%ld\n", status);
            KdPrint((num_str));
        }

        return status;
    }

    // Create the symbolic link
    status = IoCreateSymbolicLink(&SYMLINK_NAME, &DEVICE_NAME);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("FAILED to create symlink!\n"));
        IoDeleteDevice(deviceObject);
        return status;
    }

    KdPrint(("Creation successful!\n"));

    // Set up the driver object
    //DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    //DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    //DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
        DriverObject->MajorFunction[i] = DriverPassThru;

    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}

// Unload routine
extern "C" void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    IoDeleteSymbolicLink(&SYMLINK_NAME);
    IoDeleteDevice(DriverObject->DeviceObject);
    KdPrint(("Driver unloaded!\n"));
}

// Create/Close routine
//NTSTATUS DriverCreateClose([[maybe_unused]] PDEVICE_OBJECT DeviceObject, PIRP Irp)
//{
//    Irp->IoStatus.Status = STATUS_SUCCESS;
//    Irp->IoStatus.Information = 0;
//    IoCompleteRequest(Irp, IO_NO_INCREMENT);
//    return STATUS_SUCCESS;
//}

// Device control routine
extern "C" NTSTATUS DriverDeviceControl([[maybe_unused]] PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status;

    if (irpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_READ_RAW_PACKET)
    {
        // Simulated packet read for demonstration purposes
        UCHAR dummyPacket[128] = { /* Simulated packet data */ };
        const size_t packetSize = sizeof(dummyPacket);

        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < packetSize)
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            // Copy raw packet to buffer to the IRP, as the response
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, dummyPacket, packetSize);
            Irp->IoStatus.Information = packetSize; // Useful to know how much to read from buffer
            status = STATUS_SUCCESS;
        }
    }
    else
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    // Finish request and send back handled IRP
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
