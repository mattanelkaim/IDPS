// do NOT change order of includationing
#include "LayerHandles.h"
#include <ntifs.h>
#include <fwpsk.h>
#include <fwpvi.h>
#include <ntddk.h>
#include <fwpmtypes.h>
#define INITGUID
#include <guiddef.h>
#include <fwpmu.h>
#include <Netiodef.h>

// Helper Definitions
#define __IGNORE [[maybe_unused]]
// General function to variadically print with a signature
#define IDPS_PRINT(...) DbgPrint("##-IDPS_SNIFFER-##: " __VA_ARGS__)

// Blacklists definitions
#define MAX_BLACKLIST_SIZE 1024U
typedef struct ipList
{
    UINT32 ips[MAX_BLACKLIST_SIZE];
    UINT8 listLength;
} ipList;
typedef struct macList
{
    DL_EUI48 macs[MAX_BLACKLIST_SIZE];
    UINT8 listLength;
} macList;

// Initialize the blacklists
ipList ipBlacklist = { 0 };
macList macBlacklist = { 0 };

// Work item to operate at IRQL passive level
typedef struct _WORK_CONTEXT
{
    char WorkItem[128]; // 128 byte buffer to replace _IO_WORKITEM (128 is based purely on hope and prayer)
    BOOL queued;
    BOOL ongoing;
    BOOL held;
    BOOL truncFile;
    BYTE layerData[65536]; // 64KB buffer to store the layer data
    USHORT layerDataLength;
} WORK_CONTEXT, *PWORK_CONTEXT;

WORK_CONTEXT workContext = { 0 };
BOOL driverUnloading = FALSE;

// IOCTL code for user-mode communication
DEFINE_GUID(ETHERNET_CALLOUT_GUID, 0xd969fc67, 0x6fb2, 0x4504, 0x91, 0xce, 0xa9, 0x7c, 0x3c, 0x32, 0xad, 0x36);
DEFINE_GUID(ETHERNET_SUBLAYER_GUID, 0x87654321, 0xabcd, 0x0987, 0x65, 0x43, 0x21, 0x09, 0x87, 0x65, 0x43, 0x21);
DEFINE_GUID(IP_CALLOUT_GUID, 0x13579bdf, 0x2468, 0xace0, 0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0);
DEFINE_GUID(IP_SUBLAYER_GUID, 0xabcdef12, 0x3456, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90);
#define CALLOUT_DISPLAY_NAME L"EstablishedCalloutName"
#define SUBLAYER_DISPLAY_NAME L"EstablishedSublayerName"

// These cannot be const!
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\IDPS Sniffer Device");
UNICODE_STRING SYMLINK_NAME = RTL_CONSTANT_STRING(L"\\??\\SnifferDeviceLink");
UNICODE_STRING packetFilePath = RTL_CONSTANT_STRING(PACKET_FILE_PATH);

// Global variables
PDEVICE_OBJECT deviceObject = NULL;
HANDLE engineHandle = NULL;
UINT32 EthernetRegCalloutId;
UINT32 EthernetAddCalloutId;
UINT64 EthernetFilterId = 0;
UINT64 IpFilterId = 0;
UINT32 IpRegCalloutId; // USELESS??
UINT32 IpAddCalloutId; // USELESS??

// Function declarations
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DriverPassThru(__IGNORE PDEVICE_OBJECT DeviceObject, const PIRP Irp);
NTSTATUS InitializeWfp();
NTSTATUS WfpOpenEngine();
NTSTATUS WfpRegisterCallout();
NTSTATUS WfpAddCallout();
NTSTATUS WfpAddSublayer();
NTSTATUS WfpAddFilter();
VOID PacketCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut);
NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterKey, FWPS_FILTER* filter);
VOID FlowDeleteCallback(UINT16 layerId, UINT32 calloutId, UINT64 flowContext);
VOID UnInitWfp();
void writeToFile(const PUNICODE_STRING filePath, const PVOID buffer, ULONG bufferSize);
void TryQueueWorkItem(const PVOID layerData);
IO_WORKITEM_ROUTINE WorkItemRoutine;
void copyLayerData(const PVOID layerData);
void addIpRuleToBlacklist(const PUINT32 ip);
void addMacRuleToBlacklist(const PDL_EUI48 mac);
BOOL isIpInBlacklist(UINT32 ip);
BOOL isMacInBlacklist(const DL_EUI48 mac);
BOOL doesPassFirewall(const PVOID layerData);
void truncPacketFile();

// Entry point
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, __IGNORE PUNICODE_STRING RegistryPath)
{
    // Create the device
    IDPS_PRINT("Creating Device...");
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &DEVICE_NAME, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status))
    {
        IDPS_PRINT("FAILED to create device");
        return status; // Error code
    }

    // Create the symbolic link
    IDPS_PRINT("Creating SymLink...");
    status = IoCreateSymbolicLink(&SYMLINK_NAME, &DEVICE_NAME);
    if (status == STATUS_OBJECT_NAME_COLLISION)
    {
        // Replace existing symlink & update status
        IoDeleteSymbolicLink(&SYMLINK_NAME);
        status = IoCreateSymbolicLink(&SYMLINK_NAME, &DEVICE_NAME);
    }
    if (!NT_SUCCESS(status))
    {
        IDPS_PRINT("FAILED to create symlink!");
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Initialize work context
    IDPS_PRINT("Initializing work item...");
    IoInitializeWorkItem(deviceObject, (PIO_WORKITEM)&workContext.WorkItem);
    workContext.held = FALSE;
    workContext.queued = FALSE;
    workContext.ongoing = FALSE;
    workContext.truncFile = FALSE;
    workContext.layerDataLength = 0;

    // Bind functions to handling function
    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
        DriverObject->MajorFunction[i] = DriverPassThru;
    DriverObject->DriverUnload = DriverUnload;

    IDPS_PRINT("Initializing WFP...");

    status = InitializeWfp();
    if (!NT_SUCCESS(status))
    {
        // InitializeWfp() already prints err and calls UnInitWfp()
        IoDeleteDevice(deviceObject);
        IoDeleteSymbolicLink(&SYMLINK_NAME);
        return status;
    }

    IDPS_PRINT("Creation successful!");
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    // Ensure no new work items queue while unloading the driver
    driverUnloading = TRUE;
    IDPS_PRINT("Unloading driver...");
    while(workContext.ongoing) {}

    // Uninitialize stuff
    IoUninitializeWorkItem((PIO_WORKITEM)&workContext.WorkItem);
    UnInitWfp();
    IoDeleteDevice(DriverObject->DeviceObject);
    IoDeleteSymbolicLink(&SYMLINK_NAME);

    IDPS_PRINT("Driver unloaded successfully!");
}

// Handling function
NTSTATUS DriverPassThru(__IGNORE PDEVICE_OBJECT DeviceObject, const PIRP Irp)
{
    const PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS; // Assume success

    if (irpSp->MajorFunction != IRP_MJ_DEVICE_CONTROL)
        goto completeIrp;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_SEND_IP_RULE:
        addIpRuleToBlacklist(Irp->AssociatedIrp.SystemBuffer);
        break;

    case IOCTL_SEND_MAC_RULE:
        addMacRuleToBlacklist(Irp->AssociatedIrp.SystemBuffer);
        break;

    case IOCTL_TRUNCATE_FILE:
        workContext.truncFile = TRUE;
        break;

    default:
        IDPS_PRINT("Received invalid IOCTL code!");
        status = STATUS_INVALID_PARAMETER;
        break;
    }

completeIrp:
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
        IDPS_PRINT("Initialized WFP successfully");
        return STATUS_SUCCESS;
    }

    IDPS_PRINT("Error initializing WFP! (%x)", status);
    UnInitWfp();
    return status;
}

NTSTATUS WfpOpenEngine()
{
    return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
}

NTSTATUS WfpRegisterCallout()
{
    IDPS_PRINT("Registering callout...");

    // Create template for 2 callouts
    FWPS_CALLOUT callout = { 0 };
    callout.flags = 0;
    callout.notifyFn = NotifyCallback;
    callout.flowDeleteFn = FlowDeleteCallback;

    // Register callout for sniffing
    callout.calloutKey = ETHERNET_CALLOUT_GUID;
    callout.classifyFn = PacketCallback;
    return FwpsCalloutRegister(deviceObject, &callout, &EthernetRegCalloutId);
}

NTSTATUS WfpAddCallout()
{
    IDPS_PRINT("Adding callout...");

    // Create template for 2 callouts
    FWPM_CALLOUT callout = { 0 };
    callout.flags = 0;
    callout.displayData.name = CALLOUT_DISPLAY_NAME;
    callout.displayData.description = CALLOUT_DISPLAY_NAME;

    // Add callout for sniffing and blocking
    callout.calloutKey = ETHERNET_CALLOUT_GUID;
    callout.applicableLayer = FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE; // Ethernet layer
    return FwpmCalloutAdd(engineHandle, &callout, NULL, &EthernetAddCalloutId);
}

NTSTATUS WfpAddSublayer()
{
    IDPS_PRINT("Adding sublayer...");

    // Create template for 2 subLayers
    FWPM_SUBLAYER sublayer = { 0 };
    sublayer.displayData.name = SUBLAYER_DISPLAY_NAME;
    sublayer.displayData.description = SUBLAYER_DISPLAY_NAME;
    sublayer.weight = 65500; // Callback priority (between OS and NIC)

    // Add subLayer for sniffing
    sublayer.subLayerKey = ETHERNET_SUBLAYER_GUID;
    return FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
}

NTSTATUS WfpAddFilter()
{
    IDPS_PRINT("Adding filter...");

    // Create template for the filter
    FWPM_FILTER filter = { 0 };
    filter.displayData.name = SUBLAYER_DISPLAY_NAME;
    filter.displayData.description = SUBLAYER_DISPLAY_NAME;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 0; // No condition in order to receive all protocols
    filter.filterCondition = NULL; //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;

    // Add filter for sniffing
    filter.subLayerKey = ETHERNET_SUBLAYER_GUID;
    filter.action.calloutKey = ETHERNET_CALLOUT_GUID;
    filter.layerKey = FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE; // Ethernet layer
    return FwpmFilterAdd(engineHandle, &filter, NULL, &EthernetFilterId);
}

VOID PacketCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
{
    IDPS_PRINT("Received inbound packet...");

    if (!layerData || !classifyOut)
    {
        IDPS_PRINT("layerData or classifyOut is NULL");
        return;
    }

    memset(classifyOut, 0, sizeof(FWPS_CLASSIFY_OUT));

    // Check if the packet should be blocked
    if (!doesPassFirewall(layerData))
    {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }
    classifyOut->actionType = FWP_ACTION_PERMIT;

    TryQueueWorkItem(layerData);
}

// Boilerplate function without any use
NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterKey, FWPS_FILTER* filter)
{
    return STATUS_SUCCESS;
}

// Boilerplate function without any use
VOID FlowDeleteCallback(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{}

VOID UnInitWfp()
{
#define delFilter(x) if (x) {FwpmFilterDeleteById(engineHandle, x);}
#define delCallout(x) if (x) {FwpmCalloutDeleteById(engineHandle, x);}
#define unregCallout(x) if (x) {FwpsCalloutUnregisterById(x);}
    if (!engineHandle) // Nothing to uninitialize
        return;

    delFilter(EthernetFilterId);
    delFilter(IpFilterId);
    FwpmSubLayerDeleteByKey(engineHandle, &ETHERNET_SUBLAYER_GUID);
    FwpmSubLayerDeleteByKey(engineHandle, &IP_SUBLAYER_GUID);

    delCallout(EthernetAddCalloutId);
    delCallout(IpAddCalloutId);

    unregCallout(EthernetRegCalloutId);
    unregCallout(IpRegCalloutId);

    FwpmEngineClose(engineHandle);
    engineHandle = NULL;
}

void writeToFile(const PUNICODE_STRING filePath, const PVOID buffer, const ULONG bufferSize)
{
    // Handle edge-case of empty buffer
    if (!buffer)
    {
        IDPS_PRINT("writeToFile received null buffer");
        return;
    }

    // Initialize the OBJECT_ATTRIBUTES structure
    OBJECT_ATTRIBUTES objAttributes;
    InitializeObjectAttributes(
        &objAttributes,
        filePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    // Open or create the file
    IDPS_PRINT("Creating file handle");
    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = ZwCreateFile(
        &fileHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    // Check if file opened correctly
    if (!NT_SUCCESS(status))
    {
        IDPS_PRINT("Failed to open file: %x", status);
        return;
    }

    // Set the file pointer to the end of the file
    FILE_POSITION_INFORMATION filePositionInfo;
    filePositionInfo.CurrentByteOffset.QuadPart = FILE_WRITE_TO_END_OF_FILE;
    status = ZwSetInformationFile(
        fileHandle,
        &ioStatusBlock,
        &filePositionInfo,
        sizeof(FILE_POSITION_INFORMATION),
        FilePositionInformation
    );

    // Check if pointer is set correctly
    if (!NT_SUCCESS(status))
    {
        IDPS_PRINT("Failed to set file pointer: %x", status);
        goto closeFile;
    }

    // Write data to the file
    IDPS_PRINT("Writing %u bytes to file", bufferSize);
    status = ZwWriteFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        buffer,
        bufferSize,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
        IDPS_PRINT("Failed to write to file.");

closeFile:
    // Close the file handle
    IDPS_PRINT("Closing file handle");
    ZwClose(fileHandle);
}

void TryQueueWorkItem(const PVOID layerData)
{
    if (!workContext.ongoing)
    {
        // Ensure that the work item isn't released before the data is copied
        workContext.held = TRUE; // Custom mutex
        copyLayerData(layerData);
        workContext.held = FALSE;
    }

    if (workContext.queued || driverUnloading)
    {
        IDPS_PRINT("Work item already queued...");
        return;
    }

    // Queue the work item
    workContext.queued = TRUE;
    IoQueueWorkItem(
        (PIO_WORKITEM)&workContext.WorkItem,
        WorkItemRoutine,
        DelayedWorkQueue,
        &workContext
    );

    IDPS_PRINT("Work item queued successfully!");
}

void copyLayerData(const PVOID layerData)
{
    if (!layerData) // Theoretically impossible
    {
        IDPS_PRINT(__FUNCTION__ " received null pointer");
        return;
    }

    NET_BUFFER* nb = ((NET_BUFFER_LIST*)layerData)->FirstNetBuffer;
    SIZE_T totalCopied = 0;
    ULONG64 timestamp = 0;

    while (nb)
    {
        // Get the current packet data buffer length
        USHORT dataLength = (USHORT)nb->DataLength;

        // Extract the packet data buffer
        UCHAR* packetData = NdisGetDataBuffer(nb, dataLength, NULL, 1, 0);
        if (!packetData)
        {
            IDPS_PRINT("Could not read packet data from net buffer");
            return;
        }

        // Write the packet size as a 2-byte value
        dataLength += sizeof(timestamp); // Add timestamp size
        memcpy(workContext.layerData + totalCopied, &dataLength, sizeof(dataLength));
        totalCopied += sizeof(dataLength);

        // Write current timestamp as an 8-byte value
        timestamp = KeQueryUnbiasedInterruptTime();
        memcpy(workContext.layerData + totalCopied, &timestamp, sizeof(timestamp));
        totalCopied += sizeof(timestamp);

        // Write the actual packet data
        dataLength -= sizeof(timestamp); // Remove timestamp size
        memcpy(workContext.layerData + totalCopied, packetData, dataLength);
        totalCopied += dataLength;

        // Advance to next NET-BUFFER
        nb = nb->Next;
    }

    workContext.layerDataLength = (USHORT)totalCopied; // Store the actual copied size
}

void addIpRuleToBlacklist(const PUINT32 ip)
{
    // Handle edge-case of null IP
    if (!ip)
    {
        IDPS_PRINT("addRuleToBlacklist received null IP");
        return;
    }

    // Handle edge-case of full blacklisted IPs
    if (ipBlacklist.listLength == MAX_BLACKLIST_SIZE)
    {
        IDPS_PRINT("IP blacklist is full");
        return;
    }

    IDPS_PRINT("Adding rule to blacklist");
    ipBlacklist.ips[ipBlacklist.listLength++] = *ip;
}

void addMacRuleToBlacklist(const PDL_EUI48 mac)
{
    // Handle edge-case of null MAC
    if (!mac)
    {
        IDPS_PRINT("addRuleToBlacklist received null IP");
        return;
    }

    // Handle edge-case of full blacklisted MACs
    if (macBlacklist.listLength == MAX_BLACKLIST_SIZE)
    {
        IDPS_PRINT("MAC blacklist is full");
        return;
    }

    IDPS_PRINT("Adding rule to blacklist");
    memcpy(macBlacklist.macs + macBlacklist.listLength++, mac, sizeof(DL_EI48));
}

BOOL isIpInBlacklist(UINT32 ip)
{
    for (UINT8 i = 0; i < ipBlacklist.listLength; ++i)
        if (ip == ipBlacklist.ips[i])
            return TRUE;

    return FALSE;
}

BOOL isMacInBlacklist(const DL_EUI48 mac)
{
    for (UINT8 i = 0; i < macBlacklist.listLength; ++i)
        if (!memcmp(mac.Byte, macBlacklist.macs + i, sizeof(DL_EUI48)))
            return TRUE;

    return FALSE;
}

VOID WorkItemRoutine(__IGNORE PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    // Handle edge-case of empty context
    if (!Context)
    {
        IDPS_PRINT("Work item routine received null context");
        return;
    }

    PWORK_CONTEXT context = Context; // For convenience
    context->ongoing = TRUE;
    while (context->held) {} // Waite for the work item to be released

    // If the driver unloaded while the work item was still queued
    if (driverUnloading || !context->layerData)
    {
        IDPS_PRINT("Abandoning work item routine");
        context->ongoing = FALSE;
        return;
    }

    if (context->truncFile)
    {
        truncPacketFile();
        context->truncFile = FALSE;
    }

    // Write the packet data to the file
    writeToFile(&packetFilePath, workContext.layerData, workContext.layerDataLength);

    context->queued = FALSE;
    context->ongoing = FALSE;
}

BOOL doesPassFirewall(const PVOID layerData)
{
    if (!layerData) // Theoretically impossible
    {
        IDPS_PRINT("doesPassFirewall received null layerData");
        return FALSE;
    }

    // This 1 sadly CANNOT be const :(
    NET_BUFFER* nb = ((NET_BUFFER_LIST*)layerData)->FirstNetBuffer;

    const ULONG dataLength = nb->DataLength;
    const UCHAR* packetData = NdisGetDataBuffer(nb, dataLength, NULL, 1, 0);

    if (!packetData)
    {
        IDPS_PRINT("Failed to retrieve packet data");
        return FALSE;
    }

    // Check if the packet is an IP packet
    if (dataLength < sizeof(ETHERNET_HEADER))
    {
        IDPS_PRINT("Packet is too short to be an IP packet");
        return TRUE;
    }

    // Extract the Ethernet header
    const ETHERNET_HEADER* ethHeader = (ETHERNET_HEADER*)packetData;

    // Check if the packet is an IPv4 packet (EtherType == 0x0800)
    if (ethHeader->Type != 0x0008) // 0x0800 in Little Endian
    {
        IDPS_PRINT("Packet is not an IPv4 packet");
        return TRUE;
    }

    // Extract the IPv4 header
    const IPV4_HEADER* ipHeader = (IPV4_HEADER*)(packetData + sizeof(ETHERNET_HEADER));

    // Check if the source IP is in the blacklist
    if (isIpInBlacklist(ipHeader->SourceAddress.s_addr))
    {
        IDPS_PRINT("Packet blocked by IP blacklist");
        return FALSE;
    }

    // Check if the source MAC address is in the blacklist
    if (isMacInBlacklist(ethHeader->Source))
    {
        IDPS_PRINT("Packet blocked by MAC blacklist");
        return FALSE;
    }

    return TRUE;
}

void truncPacketFile()
{
    OBJECT_ATTRIBUTES objAttrs;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    NTSTATUS status;

    InitializeObjectAttributes(
        &objAttrs,
        &packetFilePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    status = ZwCreateFile(
        &fileHandle,
        GENERIC_WRITE | SYNCHRONIZE,
        &objAttrs,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        IDPS_PRINT("TruncateFile: Failed to open file (0x%08X)", status);
        return;
    }

    FILE_END_OF_FILE_INFORMATION eofInfo = { 0 };
    status = ZwSetInformationFile(
        fileHandle,
        &ioStatus,
        &eofInfo,
        sizeof(eofInfo),
        FileEndOfFileInformation
    );

    if (!NT_SUCCESS(status))
        IDPS_PRINT("TruncateFile: Failed to truncate file (0x%08X)", status);

    ZwClose(fileHandle);
}
