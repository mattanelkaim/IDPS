#include <ndis.h>
#include <ntddk.h>

// These cannot be const nor constexpr!
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\IDPS Sniffer Device");
UNICODE_STRING SYMLINK_NAME = RTL_CONSTANT_STRING(L"\\??\\SnifferDeviceLink");

// IOCTL code for user-mode communication
#define IOCTL_READ_RAW_PACKET CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

// Function declarations
extern "C" DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// Entry point
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, [[maybe_unused]] PUNICODE_STRING RegistryPath)
{
    KdPrint(("Entry!\n"));
    NTSTATUS status; // Re-used to check each API function

    PDEVICE_OBJECT deviceObject;

    // Create the device                                                        TODO: IS TYPE CORRECT??
    status = IoCreateDevice(DriverObject, sizeof(NDIS_HANDLE), &DEVICE_NAME, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("FAILED to create device!\n"));
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
    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}

// Unload routine
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
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
NTSTATUS DriverDeviceControl([[maybe_unused]] PDEVICE_OBJECT DeviceObject, PIRP Irp)
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
