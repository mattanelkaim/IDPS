#include <fwpsk.h>
#include <fwpmk.h>
#include <ntddk.h>
#define INITGUID
#include <guiddef.h> 
#include <fwpmu.h>


// These cannot be const nor constexpr!
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\IDPS Sniffer Device");
UNICODE_STRING SYMLINK_NAME = RTL_CONSTANT_STRING(L"\\??\\SnifferDeviceLink");

// Global variables
#define __IGNORE [[maybe_unused]]
#define SIGNATURE "##-IDPS_SNIFFER-##: "
#define IDPS_PRINT(x) KdPrint((SIGNATURE x)) // x is a literal string
#define IDPS_PRINT2(x1, x2) KdPrint((SIGNATURE x1, x2)) // x1 is a literal string, x2 is a char buffer
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
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DriverPassThru(__IGNORE PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS InitializeWfp();
NTSTATUS WfpOpenEngine();
NTSTATUS WfpAddCallout();
NTSTATUS WfpAddSublayer();
NTSTATUS WfpAddFilter();
NTSTATUS WfpRegisterCallout();
VOID FilterCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut);
NTSTATUS NotifyCallback(__IGNORE FWPS_CALLOUT_NOTIFY_TYPE type, __IGNORE const GUID* filterKey, __IGNORE FWPS_FILTER* filter);
VOID FlowDeleteCallback(__IGNORE UINT16 layerId, __IGNORE UINT32 calloutId, __IGNORE UINT64 flowContext);
VOID UnInitWfp();


// Entry point
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, __IGNORE PUNICODE_STRING RegistryPath)
{
    IDPS_PRINT("Entry!\n");
    NTSTATUS status; // Re-used to check each API function

    // Create the device
    status = IoCreateDevice(DriverObject, 0, &DEVICE_NAME, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status))
    {
        // Print error with status code
        if (status == STATUS_OBJECT_NAME_COLLISION)
            IDPS_PRINT("FAILED to create device: NAME_COLLISION\n");
        else
            IDPS_PRINT("FAILED to create device\n");

        return status; // Error code
    }

    // Create the symbolic link
    status = IoCreateSymbolicLink(&SYMLINK_NAME, &DEVICE_NAME);
    if (!NT_SUCCESS(status))
    {
        IDPS_PRINT("FAILED to create symlink!\n");
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Bind functions to handling function
    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
        DriverObject->MajorFunction[i] = DriverPassThru;

    DriverObject->DriverUnload = DriverUnload;

    IDPS_PRINT("Creation successful!\n");
    IDPS_PRINT("Initializing WFP...\n");
    
    status = InitializeWfp();
    if (!NT_SUCCESS(status))
    {
        // InitializeWfp() already prints err and calls UnInitWfp()
        IoDeleteDevice(deviceObject);
        return status;
    }

    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    IoDeleteSymbolicLink(&SYMLINK_NAME);
    IoDeleteDevice(DriverObject->DeviceObject);
    IDPS_PRINT("Driver unloaded!\n");
}

// Handling function
NTSTATUS DriverPassThru(__IGNORE PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    // Match request and handle properly
    switch (irpSp->MajorFunction)
    {
    case IRP_MJ_CREATE:
        IDPS_PRINT("Create request!\n");
        break;
    case IRP_MJ_CLOSE:
        IDPS_PRINT("Close request!\n");
        break;
    case IRP_MJ_READ:
        IDPS_PRINT("Read request!\n");
        break;
    default:
        break;
    }

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}


// ######## NETWORK RELATED ########


NTSTATUS InitializeWfp()
{
    if (NT_SUCCESS(WfpOpenEngine()) &&
        NT_SUCCESS(WfpRegisterCallout()) &&
        NT_SUCCESS(WfpAddCallout()) &&
        NT_SUCCESS(WfpAddSublayer()) &&
        NT_SUCCESS(WfpAddFilter()))
    {
        IDPS_PRINT("Initialized WFP successfully\n");
        return STATUS_SUCCESS;
    }

    IDPS_PRINT("Error initializing WFP!\n");
    UnInitWfp();
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WfpOpenEngine()
{
    return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
}

NTSTATUS WfpAddCallout()
{
    IDPS_PRINT("Adding callout...\n");
    wchar_t* displayName = L"EstablishedCalloutName";
    FWPM_CALLOUT callout = { 0 };
    callout.flags = 0;
    callout.displayData.name = displayName;
    callout.displayData.description = displayName;
    callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
    callout.applicableLayer = FWPM_LAYER_INBOUND_IPPACKET_V4; // receive full inbound raw packets

    return FwpmCalloutAdd(engineHandle, &callout, NULL, &AddCalloutId);
}

NTSTATUS WfpAddSublayer()
{
    IDPS_PRINT("Adding sublayer...\n");
    wchar_t* displayName = L"EstablishedSublayerName";
    FWPM_SUBLAYER sublayer = { 0 };
    sublayer.displayData.name = displayName;
    sublayer.displayData.description = displayName;
    sublayer.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID;
    sublayer.weight = 65500;
    return FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
}

NTSTATUS WfpAddFilter()
{
    IDPS_PRINT("Adding filter...\n");
    wchar_t* displayName = L"EstablishedSublayerName";
    FWPM_FILTER filter = { 0 };
    FWPM_FILTER_CONDITION condition[1] = {0};

    filter.displayData.name = displayName;
    filter.displayData.description = displayName;
    filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4; // recieve full inbound raw packets
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
    IDPS_PRINT("Registering callout...\n");
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
    //FWPS_STREAM_CALLOUT_IO_PACKET* packet = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerData;
    //FWPS_STREAM_DATA0* streamData = packet->streamData;
    //UCHAR string[1024] = { 0 };
    //ULONG length = 0;
    //SIZE_T bytes;

    //IDPS_PRINT("data is here\n");

    //RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));

    //if ((streamData->flags & FWPS_STREAM_FLAG_RECEIVE))
    //{
    //    length = streamData->dataLength <= 1024 ? streamData->dataLength : 1024; // only reading 1024 bytes from the stream (or less)
    //    FwpsCopyStreamDataToBuffer(streamData, string, length, &bytes);
    //    IDPS_PRINT2("data is %s\r\n", string);
    //}

    //packet->streamAction = FWPS_STREAM_ACTION_NONE;
    //classifyOut->actionType = FWP_ACTION_PERMIT;
    //if (filter->flags && FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
    //{
    //    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    //}

    ////////////////////////////////

    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;
    NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    UCHAR* packetData = NULL;
    ULONG packetLength = 0;

    // Ensure classifyOut is initialized
    RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));
    classifyOut->actionType = FWP_ACTION_PERMIT; // Default action

    if (!nb)
        return;

    packetLength = NET_BUFFER_DATA_LENGTH(nb);
    packetData = (UCHAR*)NdisGetDataBuffer(nb, packetLength, NULL, 1, 0);

    if (packetData)
    {
        // Log or process the raw packet data
        IDPS_PRINT2("Received raw packet of length %u\n", packetLength);
        // Perform actions with packetData here...
    }
    else
        IDPS_PRINT("Failed to access raw packet data.\n");
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
