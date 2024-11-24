#include <fwpsk.h>
#include <fwpmk.h>
#include <ntddk.h>
#define INITGUID
#include <guiddef.h> 
#include <fwpmu.h>
#include <rpc.h>

// Helper Defenitions
#define __IGNORE [[maybe_unused]]
#define SIGNATURE "##-IDPS_SNIFFER-##: "
#define IDPS_PRINT(x) KdPrint((SIGNATURE x)) // x is a literal string
#define IDPS_PRINT2(x1, x2) KdPrint((SIGNATURE x1, x2)) // x1 is a literal string, x2 is a string (char*)
#define IDPS_PRINT3(x1, x2, x3) KdPrint((SIGNATURE x1, x2, x3)) // x1 is a literal string, x2 is the buffer length, x3 is the char buffer
#define IDPS_PRINT4(x1, x2, x3, x4) KdPrint((SIGNATURE x1, x2, x3, x4)) // 4 params

// IOCTL code for user-mode communication
#define IOCTL_READ_RAW_PACKET CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
DEFINE_GUID(ETHERNET_CALLOUT_GUID, 0xd969fc67, 0x6fb2, 0x4504, 0x91, 0xce, 0xa9, 0x7c, 0x3c, 0x32, 0xad, 0x36);
DEFINE_GUID(IP_CALLOUT_GUID, 0xed6a516a, 0x36d1, 0x4881, 0xbc, 0xf0, 0xac, 0xeb, 0x4c, 0x4, 0xc2, 0x1c);
DEFINE_GUID(TRANSPORT_CALLOUT_GUID, 0x12345678, 0x9abc, 0xde0f, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0);
DEFINE_GUID(ETHERNET_SUBLAYER_GUID, 0x87654321, 0xabcd, 0x0987, 0x65, 0x43, 0x21, 0x09, 0x87, 0x65, 0x43, 0x21);
DEFINE_GUID(IP_SUBLAYER_GUID, 0x55555555, 0xaaaa, 0xaaaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa);
DEFINE_GUID(TRANSPORT_SUBLAYER_GUID, 0xbbbbbbbb, 0xbbbb, 0xbbbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb);

//UUID ETHERNET_CALLOUT_GUID, IP_CALLOUT_GUID, TRANSPORT_CALLOUT_GUID;
//UUID ETHERNET_SUBLAYER_GUID, IP_SUBLAYER_GUID, TRANSPORT_SUBLAYER_GUID;

// These cannot be const nor constexpr!
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\IDPS Sniffer Device");
UNICODE_STRING SYMLINK_NAME = RTL_CONSTANT_STRING(L"\\??\\SnifferDeviceLink");

PDEVICE_OBJECT deviceObject = NULL;
HANDLE engineHandle = NULL;
UINT32 EthernetRegCalloutId = 0, IpRegCalloutId = 0, TransportRegCalloutId = 0;
UINT32 EthernetAddCalloutId = 0, IpAddCalloutId = 0, TransportAddCalloutId = 0;
UINT64 EthernetFilterId = 0, IpFilterId = 0, TransportFilterId = 0;


// Function declarations
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DriverPassThru(__IGNORE PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS InitializeWfp();
NTSTATUS WfpOpenEngine();
NTSTATUS WfpAddCallout();
NTSTATUS WfpAddSublayer();
NTSTATUS WfpAddFilter();
NTSTATUS WfpRegisterCallout();
VOID EthernetCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut);
VOID IpCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut);
VOID TransportCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut);
NTSTATUS NotifyCallback(__IGNORE FWPS_CALLOUT_NOTIFY_TYPE type, __IGNORE const GUID* filterKey, __IGNORE FWPS_FILTER* filter);
VOID FlowDeleteCallback(__IGNORE UINT16 layerId, __IGNORE UINT32 calloutId, __IGNORE UINT64 flowContext);
VOID UnInitWfp();
//RPC_STATUS generateGUIDS();


// Entry point
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, __IGNORE PUNICODE_STRING RegistryPath)
{
    IDPS_PRINT("Entry!\n");
    NTSTATUS status; // Re-used to check each API function

    IDPS_PRINT("Generatin GUID's");  // Didn't know he was chill like dat 😜
    //if ((status = generateGUIDS()) != RPC_S_OK)
    //{
    //    IDPS_PRINT("Generating GUID's failed!");
    //    return status;
    //}

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
    if (STATUS_OBJECT_NAME_COLLISION == status)
    {
        // replacing the existing symlink
        IoDeleteSymbolicLink(&SYMLINK_NAME);
        status = IoCreateSymbolicLink(&SYMLINK_NAME, &DEVICE_NAME);
    }
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
        IoDeleteSymbolicLink(&SYMLINK_NAME);
        return status;
    }

    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UnInitWfp();
    IoDeleteDevice(DriverObject->DeviceObject);
    IoDeleteSymbolicLink(&SYMLINK_NAME);
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
    NTSTATUS status;
    if (NT_SUCCESS(status = WfpOpenEngine()) &&
        NT_SUCCESS(status = WfpRegisterCallout()) &&
        NT_SUCCESS(status = WfpAddCallout()) &&
        NT_SUCCESS(status = WfpAddSublayer()) &&
        NT_SUCCESS(status = WfpAddFilter()))
    {
        IDPS_PRINT("Initialized WFP successfully\n");
        return STATUS_SUCCESS;
    }

    IDPS_PRINT("Error initializing WFP!\n");
    IDPS_PRINT2("Error code: %x", status);
    UnInitWfp();
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WfpOpenEngine()
{
    return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
}

NTSTATUS WfpAddCallout()
{
    NTSTATUS status;

    IDPS_PRINT("Adding callout...\n");
    wchar_t* displayName = L"EstablishedCalloutName";
    FWPM_CALLOUT callout = { 0 };
    callout.flags = 0;
    callout.displayData.name = displayName;
    callout.displayData.description = displayName;

    callout.calloutKey = ETHERNET_CALLOUT_GUID;
    callout.applicableLayer = FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET; // Ethernet Layer
    status = FwpmCalloutAdd(engineHandle, &callout, NULL, &EthernetAddCalloutId);
    if (!NT_SUCCESS(status))
        return status;

    callout.calloutKey = IP_CALLOUT_GUID;
    callout.applicableLayer = FWPM_LAYER_INBOUND_IPPACKET_V4; // Ethernet Layer
    status = FwpmCalloutAdd(engineHandle, &callout, NULL, &IpAddCalloutId);
    if (!NT_SUCCESS(status))
        return status;

    callout.calloutKey = TRANSPORT_CALLOUT_GUID;
    callout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4; // Ethernet Layer
    return FwpmCalloutAdd(engineHandle, &callout, NULL, &TransportAddCalloutId);
}

NTSTATUS WfpAddSublayer()
{
    NTSTATUS status;
    IDPS_PRINT("Adding sublayer...\n");
    wchar_t* displayName = L"EstablishedSublayerName";
    FWPM_SUBLAYER sublayer = { 0 };
    sublayer.displayData.name = displayName;
    sublayer.displayData.description = displayName;
    sublayer.weight = 65500;

    sublayer.subLayerKey = ETHERNET_SUBLAYER_GUID;
    status = FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status))
        return status;

    sublayer.subLayerKey = IP_SUBLAYER_GUID;
    status = FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status))
        return status;

    sublayer.subLayerKey = TRANSPORT_SUBLAYER_GUID;
    return FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
}

NTSTATUS WfpAddFilter()
{
    NTSTATUS status;

    IDPS_PRINT("Adding filter...\n");
    wchar_t* displayName = L"EstablishedSublayerName";
    FWPM_FILTER filter = { 0 };
    filter.displayData.name = displayName;
    filter.displayData.description = displayName;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 0; // no condition in order to receive all protocols
    filter.filterCondition = NULL; // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;

    filter.subLayerKey = ETHERNET_SUBLAYER_GUID;
    filter.action.calloutKey = ETHERNET_CALLOUT_GUID;
    filter.layerKey = FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET; // Ethernet Layer
    status = FwpmFilterAdd(engineHandle, &filter, NULL, &EthernetFilterId);
    if (!NT_SUCCESS(status))
        return status;

    filter.subLayerKey = IP_SUBLAYER_GUID;
    filter.action.calloutKey = IP_CALLOUT_GUID;
    filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4; // Ip Layer
    status = FwpmFilterAdd(engineHandle, &filter, NULL, &IpFilterId);
    if (!NT_SUCCESS(status))
        return status;

    filter.subLayerKey = TRANSPORT_SUBLAYER_GUID;
    filter.action.calloutKey = TRANSPORT_CALLOUT_GUID;
    filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4; // Transport Layer
    return FwpmFilterAdd(engineHandle, &filter, NULL, &TransportFilterId);
}

NTSTATUS WfpRegisterCallout()
{
    NTSTATUS status;
    IDPS_PRINT("Registering callout...\n");
    FWPS_CALLOUT callout = { 0 };
    callout.flags = 0;
    callout.notifyFn = NotifyCallback;
    callout.flowDeleteFn = FlowDeleteCallback;

    callout.calloutKey = ETHERNET_CALLOUT_GUID;
    callout.classifyFn = EthernetCallback;
    status =  FwpsCalloutRegister(deviceObject, &callout, &EthernetRegCalloutId);
    if (!NT_SUCCESS(status))
        return status;

    callout.calloutKey = IP_CALLOUT_GUID;
    callout.classifyFn = IpCallback;
    status = FwpsCalloutRegister(deviceObject, &callout, &IpRegCalloutId);
    if (!NT_SUCCESS(status))
        return status;

    callout.calloutKey = TRANSPORT_CALLOUT_GUID;
    callout.classifyFn = TransportCallback;
    return FwpsCalloutRegister(deviceObject, &callout, &TransportRegCalloutId);
}

VOID EthernetCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
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

    // Ensure classifyOut is initialized
    RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));
    classifyOut->actionType = FWP_ACTION_PERMIT; // Default action

    // Check if layerData is not null
    if (layerData == NULL) {
        IDPS_PRINT("No data available to process.\n");
        return;
    }

    // NET_BUFFER_LIST to access packet data
    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;
    NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    UCHAR* packetData = NULL;
    ULONG packetLength = 0;
    SIZE_T totalLength = 0;  // Total length of all layers

    // Allocate memory dynamically for the raw packet buffer
    // UCHAR* rawPacketBuffer = NULL;

    // First, calculate the total length of the raw packet data
    while (nb) {
        packetLength = NET_BUFFER_DATA_LENGTH(nb);
        IDPS_PRINT2("length: %d", packetLength);
        totalLength += packetLength;
        nb = NET_BUFFER_NEXT_NB(nb);
    }
    IDPS_PRINT2("total length: %d", packetLength);

    if (totalLength == 0) {
        IDPS_PRINT("No data in packet.\n");
        return;
    }

    //// Allocate memory for the entire raw packet
    //rawPacketBuffer = (UCHAR*)ExAllocatePool2(NonPagedPool, 1, 'RawP');
    //if (rawPacketBuffer == NULL) {
    //    IDPS_PRINT("Failed to allocate memory for raw packet buffer.\n");
    //    return;
    //}

    // Reset the buffer pointer and copy data from each NET_BUFFER
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    unsigned int bytesCopied = 0;

    IDPS_PRINT("printing ethernet\n");
    while (nb) {
        packetLength = NET_BUFFER_DATA_LENGTH(nb);
        packetData = (UCHAR*)NdisGetDataBuffer(nb, packetLength, NULL, 1, 0);
        IDPS_PRINT3("%.*s ", packetLength, packetData);
        /*if (packetData && rawPacketBuffer + bytesCopied) {
            RtlCopyMemory(rawPacketBuffer + bytesCopied, packetData, packetLength);
            bytesCopied += packetLength;
        }
        else {
            IDPS_PRINT("Failed to access raw packet data.\n");
            break;
        }*/

        nb = NET_BUFFER_NEXT_NB(nb);
    }
    IDPS_PRINT("finished ethernet\n");

    // At this point, rawPacketBuffer contains the entire raw packet
    // Log or process the raw packet as needed
    IDPS_PRINT2("Raw packet captured: %X bytes\n", (int)bytesCopied);

    //IDPS_PRINT("printing ethernet\n");
    //// Optionally print the raw packet data (truncated for readability)
    //for (SIZE_T i = 0; i < min(bytesCopied, (SIZE_T)128); i++) {
    //    IDPS_PRINT3("%.*s ", bytesCopied, rawPacketBuffer);
    //}
    //IDPS_PRINT("finished ethernet\n");
}
VOID IpCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
{
    RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));
    classifyOut->actionType = FWP_ACTION_PERMIT; // Default action

    // Check if layerData is not null
    if (layerData == NULL) {
        IDPS_PRINT("No data available to process.\n");
        return;
    }

    // NET_BUFFER_LIST to access packet data
    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;
    NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    UCHAR* packetData = NULL;
    ULONG packetLength = 0;
    SIZE_T totalLength = 0;  // Total length of all layers

    // Allocate memory dynamically for the raw packet buffer
    //UCHAR* rawPacketBuffer = NULL;

    // First, calculate the total length of the raw packet data
    while (nb) {
        packetLength = NET_BUFFER_DATA_LENGTH(nb);
        IDPS_PRINT2("length: %d", packetLength);
        totalLength += packetLength;
        nb = NET_BUFFER_NEXT_NB(nb);
    }
    IDPS_PRINT2("total length: %d", packetLength);

    if (totalLength == 0) {
        IDPS_PRINT("No data in packet.\n");
        return;
    }

    //// Allocate memory for the entire raw packet
    //rawPacketBuffer = (UCHAR*)ExAllocatePool2(NonPagedPool, 1, 'RawP');
    //if (rawPacketBuffer == NULL) {
    //    IDPS_PRINT("Failed to allocate memory for raw packet buffer.\n");
    //    return;
    //}

    // Reset the buffer pointer and copy data from each NET_BUFFER
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    unsigned int bytesCopied = 0;

    IDPS_PRINT("finished ip\n");
    while (nb) {
        packetLength = NET_BUFFER_DATA_LENGTH(nb);
        packetData = (UCHAR*)NdisGetDataBuffer(nb, packetLength, NULL, 1, 0);
        IDPS_PRINT3("%.*s ", packetLength, packetData);
        /*if (packetData && rawPacketBuffer + bytesCopied) {
            RtlCopyMemory(rawPacketBuffer + bytesCopied, packetData, packetLength);
            bytesCopied += packetLength;
        }
        else {
            IDPS_PRINT("Failed to access raw packet data.\n");
            break;
        }*/

        nb = NET_BUFFER_NEXT_NB(nb);
    }
    IDPS_PRINT("finished ip\n");

    // At this point, rawPacketBuffer contains the entire raw packet
    // Log or process the raw packet as needed
    IDPS_PRINT2("Raw packet captured: %X bytes\n", (int)bytesCopied);

    //IDPS_PRINT("printing ip\n");
    //// Optionally print the raw packet data (truncated for readability)
    //for (SIZE_T i = 0; i < min(bytesCopied, (SIZE_T)128); i++) {
    //    IDPS_PRINT3("%.*s ", bytesCopied, rawPacketBuffer);
    //}
    //IDPS_PRINT("finished ip\n");
}
VOID TransportCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
{
    RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));
    classifyOut->actionType = FWP_ACTION_PERMIT; // Default action

    // Check if layerData is not null
    if (layerData == NULL) {
        IDPS_PRINT("No data available to process.\n");
        return;
    }

    // NET_BUFFER_LIST to access packet data
    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;
    NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    UCHAR* packetData = NULL;
    ULONG packetLength = 0;
    SIZE_T totalLength = 0;  // Total length of all layers

    // Allocate memory dynamically for the raw packet buffer
    // UCHAR* rawPacketBuffer = NULL;

    // First, calculate the total length of the raw packet data
    while (nb) {
        packetLength = NET_BUFFER_DATA_LENGTH(nb);
        IDPS_PRINT2("length: %d", packetLength);
        totalLength += packetLength;
        nb = NET_BUFFER_NEXT_NB(nb);
    }
    IDPS_PRINT2("total length: %d", packetLength);

    if (totalLength == 0) {
        IDPS_PRINT("No data in packet.\n");
        return;
    }

    //// Allocate memory for the entire raw packet
    //rawPacketBuffer = (UCHAR*)ExAllocatePool2(NonPagedPool, 1, 'RawP');
    //if (rawPacketBuffer == NULL) {
    //    IDPS_PRINT("Failed to allocate memory for raw packet buffer.\n");
    //    return;
    //}

    // Reset the buffer pointer and copy data from each NET_BUFFER
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    unsigned int bytesCopied = 0;

    IDPS_PRINT("printing transport\n");
    while (nb) {
        packetLength = NET_BUFFER_DATA_LENGTH(nb);
        packetData = (UCHAR*)NdisGetDataBuffer(nb, packetLength, NULL, 1, 0);

        IDPS_PRINT3("%.*s ", packetLength, packetData);

        /*if (packetData && rawPacketBuffer + bytesCopied) {
            RtlCopyMemory(rawPacketBuffer + bytesCopied, packetData, packetLength);
            bytesCopied += packetLength;
        }
        else {
            IDPS_PRINT("Failed to access raw packet data.\n");
            break;
        }*/

        nb = NET_BUFFER_NEXT_NB(nb);
    }
    IDPS_PRINT("finished transport\n");

    // At this point, rawPacketBuffer contains the entire raw packet
    // Log or process the raw packet as needed
    IDPS_PRINT2("Raw packet captured: %X bytes\n", (int)bytesCopied);

    //IDPS_PRINT("printing transport\n");
    // Optionally print the raw packet data (truncated for readability)
    /*for (SIZE_T i = 0; i < min(bytesCopied, (SIZE_T)128); i++) {
        IDPS_PRINT3("%.*s ", bytesCopied, rawPacketBuffer);
    }*/
    //IDPS_PRINT("finished transport\n");
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

#define delFilter(x) if (x) {FwpmFilterDeleteById(engineHandle, x);}
#define delCallout(x) if (x) {FwpmCalloutDeleteById(engineHandle, x);}
#define unregCallout(x) if (x) {FwpsCalloutUnregisterById(x);}
VOID UnInitWfp()
{
    if (!engineHandle)
        return;

    delFilter(EthernetFilterId);
    delFilter(IpFilterId);
    delFilter(TransportFilterId);
    FwpmSubLayerDeleteByKey(engineHandle, &ETHERNET_SUBLAYER_GUID);
    FwpmSubLayerDeleteByKey(engineHandle, &IP_SUBLAYER_GUID);
    FwpmSubLayerDeleteByKey(engineHandle, &TRANSPORT_SUBLAYER_GUID);

    delCallout(EthernetAddCalloutId);
    delCallout(IpAddCalloutId);
    delCallout(TransportAddCalloutId);

    unregCallout(EthernetRegCalloutId);
    unregCallout(IpRegCalloutId);
    unregCallout(TransportRegCalloutId);

    FwpmEngineClose(engineHandle);
    engineHandle = NULL;
}

//RPC_STATUS generateGUIDS()
//{
//    RPC_STATUS status;
//    if ((status = UuidCreate(&ETHERNET_CALLOUT_GUID)) != RPC_S_OK ||
//        (status = UuidCreate(&IP_CALLOUT_GUID)) != RPC_S_OK ||
//        (status = UuidCreate(&TRANSPORT_CALLOUT_GUID)) != RPC_S_OK ||
//        (status = UuidCreate(&ETHERNET_SUBLAYER_GUID)) != RPC_S_OK ||
//        (status = UuidCreate(&IP_SUBLAYER_GUID)) != RPC_S_OK ||
//        (status = UuidCreate(&TRANSPORT_SUBLAYER_GUID)) != RPC_S_OK)
//    {
//        return status;
//    }
//    return RPC_S_OK;
//
//}