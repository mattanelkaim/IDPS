// do NOT change order of includationing
#include "LayerHandles.h"
#include <ntifs.h>
#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#define INITGUID
#include <guiddef.h>
#include <fwpmu.h>
#include <Netiodef.h>

// Helper Definitions
#define __IGNORE [[maybe_unused]]
#define SIGNATURE "##-IDPS_SNIFFER-##: "
#define IDPS_PRINT(x) KdPrint((SIGNATURE x)) // x is a literal string
#define IDPS_PRINT2(x1, x2) KdPrint((SIGNATURE x1, x2)) // x1 is a literal string, x2 is a string (char*)
#define IDPS_PRINT3(x1, x2, x3) KdPrint((SIGNATURE x1, x2, x3)) // x1 is a literal string, x2 is the buffer length, x3 is the char buffer
#define IDPS_PRINT4(x1, x2, x3, x4) KdPrint((SIGNATURE x1, x2, x3, x4)) // 4 parameters

#define CALLOUT_DISPLAY_NAME L"EstablishedCalloutName"
#define SUBLAYER_DISPLAY_NAME L"EstablishedSublayerName"

#define MAX_BLACKLIST_SIZE 1024U
typedef struct ipList
{
    UINT32 ips[MAX_BLACKLIST_SIZE]; // 4KB buffer to store the IP blacklist
    UINT8 listLength;
} ipList;

typedef struct macList
{
    DL_EUI48 macs[MAX_BLACKLIST_SIZE]; // 6KB buffer to store the IP blacklist
    UINT8 listLength;
} macList;

// Initializing the blacklists
ipList ipBlacklist = { 0 };
macList macBlacklist = { 0 };

// work item to operate at IRQL passive level
typedef struct _WORK_CONTEXT
{
    char WorkItem[128]; // A 128 byte buffer to replace _IO_WORKITEM (128 is based purely on hope and prayer)
    BOOL queued;
    BOOL ongoing;
    BOOL held;
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

// These cannot be const nor constexpr!
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\IDPS Sniffer Device");
UNICODE_STRING SYMLINK_NAME = RTL_CONSTANT_STRING(L"\\??\\SnifferDeviceLink");

PDEVICE_OBJECT deviceObject = NULL;
HANDLE engineHandle = NULL;
UINT32 EthernetRegCalloutId;
UINT32 EthernetAddCalloutId;
UINT64 EthernetFilterId = 0;
UINT32 IpRegCalloutId;
UINT32 IpAddCalloutId;
UINT64 IpFilterId = 0;
HANDLE packetMutex = NULL;
HANDLE workMutex = NULL;
KERNEL_OBJECTS kernelMutexObjects = { NULL, NULL, NULL, NULL };

UNICODE_STRING packetMutexPath;
UNICODE_STRING packetFilePath;

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
NTSTATUS InitFileNames();
VOID UnInitMutexes();
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
    IDPS_PRINT("Entry!\n");
    NTSTATUS status; // Re-used to check each API function

    // Create the device
    IDPS_PRINT("Creating Device...\n");
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
    IDPS_PRINT("Creating SymLink...\n");
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

    // Initializing work context
    IDPS_PRINT("Initializing work item...\n");
    IoInitializeWorkItem(deviceObject, (PIO_WORKITEM)&workContext.WorkItem);
    workContext.queued = FALSE;
    workContext.ongoing = FALSE;
    workContext.held = FALSE;
    workContext.layerDataLength = 0;

    // Bind functions to handling function
    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
        DriverObject->MajorFunction[i] = DriverPassThru;
    DriverObject->DriverUnload = DriverUnload;

    IDPS_PRINT("Initializing WFP...\n");

    status = InitializeWfp();
    if (!NT_SUCCESS(status))
    {
        // InitializeWfp() already prints err and calls UnInitWfp()
        IoDeleteDevice(deviceObject);
        IoDeleteSymbolicLink(&SYMLINK_NAME);
        return status;
    }

    IDPS_PRINT("Creation successful!\n");

    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    driverUnloading = TRUE; // insuring no new work items queue while unloading the driver
    IDPS_PRINT("Unloading driver...\n");
    while(workContext.ongoing) {}
    IoUninitializeWorkItem((PIO_WORKITEM)&workContext.WorkItem);
    UnInitWfp();
    IoDeleteDevice(DriverObject->DeviceObject);
    IoDeleteSymbolicLink(&SYMLINK_NAME);
    IDPS_PRINT("Driver unloaded successfully!\n");
}

// Handling function
NTSTATUS DriverPassThru(__IGNORE PDEVICE_OBJECT DeviceObject, const PIRP Irp)
{
    const PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    if (irpSp->MajorFunction != IRP_MJ_DEVICE_CONTROL)
    {
        IDPS_PRINT("Received invalid IOCTL code!\n");
        status = STATUS_INVALID_PARAMETER;
    }

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_SEND_IP_RULE:
        addIpRuleToBlacklist(Irp->AssociatedIrp.SystemBuffer);
        break;

    case IOCTL_SEND_MAC_RULE:
        addMacRuleToBlacklist(Irp->AssociatedIrp.SystemBuffer);
        break;

    case IOCTL_TRUNCATE_FILE:
        truncPacketFile();
        break;

    default:
        IDPS_PRINT("Received invalid IOCTL code!\n");
        status = STATUS_INVALID_PARAMETER;
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
    if (NT_SUCCESS(status = InitFileNames()) &&
        NT_SUCCESS(status = WfpOpenEngine()) &&
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
    return status;
}

NTSTATUS WfpOpenEngine()
{
    return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
}

NTSTATUS WfpRegisterCallout()
{
    IDPS_PRINT("Registering callout...\n");

    // Creating template for 2 callouts
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
    IDPS_PRINT("Adding callout...\n");

    // Creating template for 2 callouts
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
    IDPS_PRINT("Adding sublayer...\n");

    // Creating template for 2 subLayers
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
    IDPS_PRINT("Adding filter...\n");

    // Creating template for the filter
    FWPM_FILTER filter = { 0 };
    filter.displayData.name = SUBLAYER_DISPLAY_NAME;
    filter.displayData.description = SUBLAYER_DISPLAY_NAME;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 0; // no condition in order to receive all protocols
    filter.filterCondition = NULL; // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
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
        IDPS_PRINT("Layer data or classifyOut is NULL");
        return;
    }

    memset(classifyOut, 0, sizeof(FWPS_CLASSIFY_OUT));

    // Checking if the packet should be blocked
    if (!doesPassFirewall(layerData))
    {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }
    classifyOut->actionType = FWP_ACTION_PERMIT;
        
    IDPS_PRINT("queueing work item");
    TryQueueWorkItem(layerData);
}

// Boilerplate function without any use for now
NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterKey, FWPS_FILTER* filter)
{
    return STATUS_SUCCESS;
}

// Boilerplate function without any use for now
VOID FlowDeleteCallback(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
    // Noting here!
}

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

    UnInitMutexes();
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
    IDPS_PRINT("Initializing file attributes");
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
        IDPS_PRINT2("Failed to open file: %x", status);
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
        IDPS_PRINT2("Failed to set file pointer: %x", status);
        goto closeFile;
    }

    // Write data to the file
    IDPS_PRINT2("Writing %u bytes to file", bufferSize);
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
    // Closing the file handle
    IDPS_PRINT("Closing file handle");
    ZwClose(fileHandle);
}

void TryQueueWorkItem(const PVOID layerData)
{
    if (!workContext.ongoing)
    {
        // Making sure that the work item isn't released before the data is copied
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

NTSTATUS InitFileNames()
{
    IDPS_PRINT("Initializing file names...");

    RtlInitUnicodeString(&packetFilePath, PACKET_FILE_PATH);
    RtlInitUnicodeString(&packetMutexPath, PACKET_MUTEX_PATH);

    return STATUS_SUCCESS;
}

VOID UnInitMutexes()
{
    ZwClose(packetMutex);
}

void copyLayerData(const PVOID layerData)
{
    if (!layerData) // Theoretically impossible
    {
        IDPS_PRINT(__FUNCTION__ " received null pointer");
        return;
    }

    const NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;
    NET_BUFFER* nb = nbl->FirstNetBuffer;
    SIZE_T totalCopied = 0;
    ULONG64 timestamp = 0;

    while (nb)
    {
        // Getting the current packet data buffer length
        USHORT dataLength = (USHORT)nb->DataLength;

        // Extracting the packet data buffer
        UCHAR* packetData = NdisGetDataBuffer(nb, dataLength, NULL, 1, 0);
        if (!packetData)
        {
            IDPS_PRINT("could not read packet data from net buffer");
            return;
        }

        // Writing the packet size as a 2-byte value
		dataLength += sizeof(timestamp); // Adding timestamp size
        memcpy(workContext.layerData + totalCopied, &dataLength, sizeof(dataLength));
        totalCopied += sizeof(dataLength);

        // Writing current timestamp as an 8-byte value
        timestamp = KeQueryUnbiasedInterruptTime();
        memcpy(workContext.layerData + totalCopied, &timestamp, sizeof(timestamp));
        totalCopied += sizeof(timestamp);

        // Writing the actual packet data
		dataLength -= sizeof(timestamp); // Removing timestamp size
        memcpy(workContext.layerData + totalCopied, packetData, dataLength);
        totalCopied += dataLength;

        // Advancing to next NET-BUFFER
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
    // Handle edge-case of null IP
    if (!mac)
    {
        IDPS_PRINT("addRuleToBlacklist received null IP");
        return;
    }

    // Handle edge-case of full blacklisted IPs
    if (macBlacklist.listLength == MAX_BLACKLIST_SIZE)
    {
        IDPS_PRINT("IP blacklist is full");
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
    while (context->held) {} // Waiting for the work item to be released

    // If the driver unloaded while the work item was still queued
    if (driverUnloading || !context->layerData)
    {
        IDPS_PRINT("Abandoning work item routine");
        context->ongoing = FALSE;
        return;
    }

    IDPS_PRINT("Started work item routine!");

	// Printing the packet data
    USHORT i;
    for (i = 0; i + 64 < workContext.layerDataLength; i += 64)
        IDPS_PRINT3("%.*s", 64, workContext.layerData + i);
    IDPS_PRINT3("%.*s", workContext.layerDataLength - i, workContext.layerData + i);

    // Writing the packet data to the file
    writeToFile(&packetFilePath, workContext.layerData, workContext.layerDataLength);

    context->queued = FALSE;
    context->ongoing = FALSE;
    IDPS_PRINT("Finished work item routine");
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
    const UCHAR* packetData = (UCHAR*)NdisGetDataBuffer(nb, dataLength, NULL, 1, 0);

    if (!packetData)
    {
        IDPS_PRINT("Failed to retrieve packet data");
        return FALSE;
    }

    // Checking if the packet is an IP packet
    if (dataLength < sizeof(ETHERNET_HEADER))
    {
        IDPS_PRINT("Packet is too short to be an IP packet");
        return TRUE;
    }

    // Extracting the Ethernet header
    const ETHERNET_HEADER* ethHeader = (ETHERNET_HEADER*)packetData;

    // Check if the packet is an IPv4 packet (EtherType == 0x0800)
    if (ethHeader->Type != 0x0008) // 0x0008 is RtlUshortByteSwap(0x0800)
    {
        IDPS_PRINT("Packet is not an IPv4 packet");
        return TRUE;
    }

    // Extracting the IPv4 header
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
    // waiting for the work item to finish
    while (workContext.ongoing) {}
    workContext.held = TRUE;

    OBJECT_ATTRIBUTES objAttrs;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    NTSTATUS status;

    InitializeObjectAttributes(&objAttrs,
        &packetFilePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwCreateFile(&fileHandle,
        GENERIC_WRITE | SYNCHRONIZE,
        &objAttrs,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (!NT_SUCCESS(status))
        IDPS_PRINT2("TruncateFile: Failed to open file (0x%08X)\n", status);

    FILE_END_OF_FILE_INFORMATION eofInfo = { 0 };
    status = ZwSetInformationFile(fileHandle,
        &ioStatus,
        &eofInfo,
        sizeof(eofInfo),
        FileEndOfFileInformation);

    if (!NT_SUCCESS(status)) {
        IDPS_PRINT2("TruncateFile: Failed to truncate file (0x%08X)\n", status);
    }

    ZwClose(fileHandle);

    // freeing the work item
    workContext.held = FALSE;
}
