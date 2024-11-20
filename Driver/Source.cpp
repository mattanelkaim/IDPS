#include <fwpsk.h>
#include <fwpmk.h>
#include <ntddk.h>
#define INITGUID
#include <guiddef.h> 
#include <fwpmu.h>
#include <stdio.h>
//#include <Windows.h>
//#include <ndis.h>
//#include <ntdef.h>
//#include <wchar.h>


// These cannot be const nor constexpr!
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\IDPS Sniffer Device");
UNICODE_STRING SYMLINK_NAME = RTL_CONSTANT_STRING(L"\\??\\SnifferDeviceLink");

// Global variables
#define __IGNORE [[maybe_unused]]
PDEVICE_OBJECT deviceObject = NULL;
HANDLE engineHandle = NULL;
UINT32 RegCalloutId = 0;
UINT32 AddCalloutId = 0;
UINT64 FilterId = 0;

// IOCTL code for user-mode communication
#define IOCTL_READ_RAW_PACKET CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID, 0xd969fc67, 0x6fb2, 0x4504, 0x91, 0xce, 0xa9, 0x7c, 0x3c, 0x32, 0xad, 0x36);
DEFINE_GUID(WFP_SAMPLE_SUB_LAYER_GUID, 0xed6a516a, 0x36d1, 0x4881, 0xbc, 0xf0, 0xac, 0xeb, 0x4c, 0x4, 0xc2, 0x1c);

// Function declarations
extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject);
//extern "C" NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
extern "C" NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
extern "C" NTSTATUS DriverPassThru(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS WfpOpenEngine();
NTSTATUS WfpAddCallout();
NTSTATUS WfpAddSublayer();
VOID UnInitWfp();
NTSTATUS InitializeWfp();
NTSTATUS WfpAddFilter();
NTSTATUS WfpRegisterCallout();
VOID FilterCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut);
NTSTATUS NotifyCallback(__IGNORE FWPS_CALLOUT_NOTIFY_TYPE type, __IGNORE const GUID* filterKey, __IGNORE FWPS_FILTER* filter);
VOID FlowDeleteCallback(__IGNORE UINT16 layerId, __IGNORE UINT32 calloutId, __IGNORE UINT64 flowContext);


// Entry point
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, [[maybe_unused]] PUNICODE_STRING RegistryPath)
{
    KdPrint(("Entry!\n"));
    NTSTATUS status; // Re-used to check each API function


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
            //sprintf(num_str, "%ld\n", status);
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

    KdPrint(("Initializing WFP\r\n"));
    InitializeWfp();

    return STATUS_SUCCESS;
}

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

// Handling function
NTSTATUS DriverPassThru([[maybe_unused]] PDEVICE_OBJECT DeviceObject, PIRP Irp)
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


// ######## NETWORK RELATED ########

NTSTATUS WfpOpenEngine()
{
    return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
}

NTSTATUS WfpAddCallout()
{
    KdPrint(("Adding callout...\n"));
    wchar_t* displayName = L"EstablishedCalloutName";
    FWPM_CALLOUT callout = { 0 };
    callout.flags = 0;
    callout.displayData.name = displayName;
    callout.displayData.description = displayName;
    callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
    callout.applicableLayer = FWPM_LAYER_STREAM_V4;

    KdPrint(("Almost done adding callout...\n"));

    NTSTATUS status = FwpmCalloutAdd(engineHandle, &callout, NULL, &AddCalloutId);
    // Debug print
    char str[20 + sizeof(char)];
    sprintf(str, "%lu", status);
    KdPrint((str));
    return status;
}

NTSTATUS WfpAddSublayer()
{
    KdPrint(("Adding sublayer...\n"));
    wchar_t* displayName = L"EstablishedSublayerName";
    FWPM_SUBLAYER sublayer = { 0 };
    sublayer.displayData.name = displayName;
    sublayer.displayData.description = displayName;
    sublayer.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID;
    sublayer.weight = 65500;
    return FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
}

VOID UnInitWfp()
{
    if (!engineHandle)
        return;

    if (FilterId != 0)
    {
        FwpmFilterDeleteById(engineHandle, FilterId);
        FwpmSubLayerDeleteByKey(engineHandle, &WFP_SAMPLE_SUB_LAYER_GUID);
    }

    if (AddCalloutId != 0)
    {
        FwpmCalloutDeleteById(engineHandle, AddCalloutId);
    }

    if (RegCalloutId != 0)
    {
        FwpsCalloutUnregisterById(RegCalloutId);
    }

    FwpmEngineClose(engineHandle);
    engineHandle = NULL;
}

NTSTATUS InitializeWfp()
{
    if (NT_SUCCESS(WfpOpenEngine()) &&
        NT_SUCCESS(WfpRegisterCallout()) &&
        NT_SUCCESS(WfpAddCallout()) &&
        NT_SUCCESS(WfpAddSublayer()) &&
        NT_SUCCESS(WfpAddFilter()))
    {
        KdPrint(("Initialized successfully\n"));
        return STATUS_SUCCESS;
    }

    KdPrint(("Error initializing!\n"));
    UnInitWfp();
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WfpAddFilter()
{
    KdPrint(("Adding filter...\n"));
    wchar_t* displayName = L"EstablishedSublayerName";
    FWPM_FILTER filter = { 0 };
    FWPM_FILTER_CONDITION condition[1] = {0};

    filter.displayData.name = displayName;
    filter.displayData.description = displayName;
    filter.layerKey = FWPM_LAYER_STREAM_V4;
    filter.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 1;
    filter.filterCondition = condition;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;

    condition[0].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    condition[0].matchType = FWP_MATCH_LESS_OR_EQUAL;
    condition[0].conditionValue.type = FWP_UINT16;
    condition[0].conditionValue.uint16 = 65000;

    return FwpmFilterAdd(engineHandle, &filter, NULL, &FilterId);
}

NTSTATUS WfpRegisterCallout()
{
    KdPrint(("Registering callout...\n"));
    FWPS_CALLOUT callout = { 0 };
    callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
    callout.flags = 0;
    callout.classifyFn = FilterCallback;
    callout.notifyFn = NotifyCallback;
    callout.flowDeleteFn = FlowDeleteCallback;

    return FwpsCalloutRegister(deviceObject, &callout, &RegCalloutId);
}

VOID FilterCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
{
    FWPS_STREAM_CALLOUT_IO_PACKET* packet;
    KdPrint(("data is here\r\n"));

    packet = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerData;

    RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));

    packet->streamAction = FWPS_STREAM_ACTION_NONE;
    classifyOut->actionType = FWP_ACTION_PERMIT;
    if (filter->flags && FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
    {
        classifyOut->actionType &= FWPS_RIGHT_ACTION_WRITE;
    }
}

// Boilerplate function without any use for now
NTSTATUS NotifyCallback(__IGNORE FWPS_CALLOUT_NOTIFY_TYPE type, __IGNORE const GUID* filterKey, __IGNORE FWPS_FILTER* filter)
{
    return STATUS_SUCCESS;
}

// Boilerplate function without any use for now
VOID FlowDeleteCallback(__IGNORE UINT16 layerId, __IGNORE UINT32 calloutId, __IGNORE UINT64 flowContext)
{
    // Noting here!
}

