// do NOT change order of includation
#include <fwpsk.h>
#include <fwpstypes.h>
#include <fwpmk.h>
#define INITGUID
#include <guiddef.h>
#include <fwpmu.h>

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
DEFINE_GUID(APPLICATION_CALLOUT_GUID, 0x13579bdf, 0x2468, 0xace0, 0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0);
DEFINE_GUID(ETHERNET_SUBLAYER_GUID, 0x87654321, 0xabcd, 0x0987, 0x65, 0x43, 0x21, 0x09, 0x87, 0x65, 0x43, 0x21);
DEFINE_GUID(IP_SUBLAYER_GUID, 0x55555555, 0xaaaa, 0xaaaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa);
DEFINE_GUID(TRANSPORT_SUBLAYER_GUID, 0xbbbbbbbb, 0xbbbb, 0xbbbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb);
DEFINE_GUID(APPLICATION_SUBLAYER_GUID, 0xabcdef12, 0x3456, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90);

// These cannot be const nor constexpr!
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\IDPS Sniffer Device");
UNICODE_STRING SYMLINK_NAME = RTL_CONSTANT_STRING(L"\\??\\SnifferDeviceLink");

#define BASE_FILE_DIRECTORY L"\\??\\C:\\IDPS_shared_files\\"
#define ETHERNET_FILE_PATH (BASE_FILE_DIRECTORY L"ethernet.txt")
#define INTERNET_FILE_PATH (BASE_FILE_DIRECTORY L"internet.txt")
#define TRANSPORT_FILE_PATH (BASE_FILE_DIRECTORY L"transport.txt")
#define APPLICATION_FILE_PATH (BASE_FILE_DIRECTORY L"application.txt")
#define BASE_MUTEX_DIRECTORY L"\\BaseNamedObjects\\"
#define ETHERNET_MUTEX_PATH (BASE_MUTEX_DIRECTORY L"ethernetMutex")
#define INTERNET_MUTEX_PATH (BASE_MUTEX_DIRECTORY L"internetMutex")
#define TRANSPORT_MUTEX_PATH (BASE_MUTEX_DIRECTORY L"transportMutex")
#define APPLICATION_MUTEX_PATH (BASE_MUTEX_DIRECTORY L"applicationMutex")

PDEVICE_OBJECT deviceObject = NULL;
HANDLE engineHandle = NULL;
UINT32 EthernetRegCalloutId = 0, IpRegCalloutId = 0, TransportRegCalloutId = 0, ApplicationRegCalloutId = 0;
UINT32 EthernetAddCalloutId = 0, IpAddCalloutId = 0, TransportAddCalloutId = 0, ApplicationAddCalloutId = 0;
UINT64 EthernetFilterId = 0, IpFilterId = 0, TransportFilterId = 0, ApplicationFilterId = 0;
HANDLE ethernetMutex, internetMutex, transportMutex, applicationMutex;
UNICODE_STRING ethernetMutexPath, internetMutexPath, transportMutexPath, applicationMutexPath;
UNICODE_STRING ethernetFilePath, internetFilePath, transportFilePath, applicationFilePath;


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
VOID ApplicationCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut);
NTSTATUS NotifyCallback(__IGNORE FWPS_CALLOUT_NOTIFY_TYPE type, __IGNORE const GUID* filterKey, __IGNORE FWPS_FILTER* filter);
VOID FlowDeleteCallback(__IGNORE UINT16 layerId, __IGNORE UINT32 calloutId, __IGNORE UINT64 flowContext);
VOID UnInitWfp();
void writeNetBufferToFile(void* list, FWPS_CLASSIFY_OUT* classifyOut, PUNICODE_STRING Filepath, PHANDLE mutexName);
NTSTATUS WriteToFile(PUNICODE_STRING filePath, PVOID buffer, ULONG bufferSize, PHANDLE mutex);
NTSTATUS InitMutexesAndFiles();

NTSTATUS NTAPI NtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NTAPI NtClose(IN HANDLE Handle);
//NTSTATUS NTAPI ZwOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#if 0
NTSTATUS NTAPI NtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {}
NTSTATUS NTAPI NtClose(IN HANDLE Handle) {}
NTSTATUS NTAPI ZwOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {}
#endif

//extern "C" __declspec(dllexport) NTSTATUS NTAPI NtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
//extern "C" __declspec(dllexport) NTSTATUS NTAPI NtClose(IN HANDLE Handle);


// Entry point
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, __IGNORE PUNICODE_STRING RegistryPath)
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
    callout.applicableLayer = FWPM_LAYER_INBOUND_IPPACKET_V4; // Ip Layer
    status = FwpmCalloutAdd(engineHandle, &callout, NULL, &IpAddCalloutId);
    if (!NT_SUCCESS(status))
        return status;

    callout.calloutKey = TRANSPORT_CALLOUT_GUID;
    callout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4; // Transport Layer
    status = FwpmCalloutAdd(engineHandle, &callout, NULL, &TransportAddCalloutId);
    if (!NT_SUCCESS(status))
        return status;

    callout.calloutKey = APPLICATION_CALLOUT_GUID;
    callout.applicableLayer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4; // Application Layer
    return FwpmCalloutAdd(engineHandle, &callout, NULL, &ApplicationAddCalloutId);
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
    status = FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status))
        return status;

    sublayer.subLayerKey = APPLICATION_SUBLAYER_GUID;
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
    status = FwpmFilterAdd(engineHandle, &filter, NULL, &TransportFilterId);
    if (!NT_SUCCESS(status))
        return status;

    filter.subLayerKey = APPLICATION_SUBLAYER_GUID;
    filter.action.calloutKey = APPLICATION_CALLOUT_GUID;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4; // Application Layer
    return FwpmFilterAdd(engineHandle, &filter, NULL, &ApplicationFilterId);
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
    status = FwpsCalloutRegister(deviceObject, &callout, &TransportRegCalloutId);
    if (!NT_SUCCESS(status))
        return status;

    callout.calloutKey = APPLICATION_CALLOUT_GUID;
    callout.classifyFn = ApplicationCallback;
    return FwpsCalloutRegister(deviceObject, &callout, &ApplicationRegCalloutId);
}

VOID EthernetCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
{
    
}
VOID IpCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
{
}
VOID TransportCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
{
}
VOID ApplicationCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
{
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
void writeNetBufferToFile(void* list, FWPS_CLASSIFY_OUT* classifyOut, PUNICODE_STRING Filepath, PHANDLE mutexName)
{
    // Ensure classifyOut is initialized
    RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));
    classifyOut->actionType = FWP_ACTION_PERMIT; // Default action

    // Check if layerData is not null
    if (!list)
        return;

    // NET_BUFFER_LIST to access packet data
    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)list;
    NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    UCHAR* packetData = NULL;
    ULONG packetLength = 0;
    SIZE_T totalLength = 0;  // Total length of all layers

    // Reset the buffer pointer and copy data from each NET_BUFFER
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    while (nb) {
        packetLength = NET_BUFFER_DATA_LENGTH(nb);
        packetData = (UCHAR*)NdisGetDataBuffer(nb, packetLength, NULL, 1, 0);
        IDPS_PRINT3("%.*s ", packetLength, packetData);

        nb = NET_BUFFER_NEXT_NB(nb);
    }
}

NTSTATUS WriteToFile(PUNICODE_STRING filePath, PVOID buffer, ULONG bufferSize, PHANDLE mutex)
{
    OBJECT_ATTRIBUTES objAttributes;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;

    // Wait for the mutex
    KeWaitForSingleObject(mutex, Executive, KernelMode, FALSE, NULL);

    // Initialize the OBJECT_ATTRIBUTES structure
    InitializeObjectAttributes(&objAttributes, filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    // Open or create the file
    status = ZwCreateFile(
        &fileHandle,
        GENERIC_WRITE,
        &objAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        // Release the mutex before returning
        KeReleaseMutex((PKMUTEX)mutex, FALSE);
        return status; // Return if file creation failed
    }

    // Write data to the file
    status = ZwWriteFile(
        fileHandle,
        NULL,                      // Event (optional)
        NULL,                      // APC routine (optional)
        NULL,                      // APC context (optional)
        &ioStatusBlock,
        buffer,
        bufferSize,
        NULL,                      // Byte offset (NULL for append/write at current)
        NULL                       // Key (optional for I/O operations)
    );

    // Close the file handle
    ZwClose(fileHandle);

    // Release the mutex
    KeReleaseMutex((PKMUTEX)mutex, FALSE);

    return status;
}

NTSTATUS InitMutexesAndFiles()
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttributes;

    RtlInitUnicodeString(&ethernetFilePath, ETHERNET_FILE_PATH);
    RtlInitUnicodeString(&internetFilePath, INTERNET_FILE_PATH);
    RtlInitUnicodeString(&transportFilePath, TRANSPORT_FILE_PATH);
    RtlInitUnicodeString(&applicationFilePath, APPLICATION_FILE_PATH);
    RtlInitUnicodeString(&ethernetMutexPath, ETHERNET_MUTEX_PATH);
    RtlInitUnicodeString(&internetMutexPath, INTERNET_MUTEX_PATH);
    RtlInitUnicodeString(&transportMutexPath, TRANSPORT_MUTEX_PATH);
    RtlInitUnicodeString(&applicationMutexPath, APPLICATION_MUTEX_PATH);

    // Open Ethernet Mutex
    InitializeObjectAttributes(&objAttributes, &ethernetMutexPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = NtOpenMutant(&ethernetMutex, ((0x000F0000L) | (0x00100000L) | 0x0001), &objAttributes);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to open Ethernet mutex: 0x%08X\n", status);
        return status;
    }

    // Open Internet Mutex
    InitializeObjectAttributes(&objAttributes, &internetMutexPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = NtOpenMutant(&internetMutex, ((0x000F0000L) | (0x00100000L) | 0x0001), &objAttributes);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to open Internet mutex: 0x%08X\n", status);
        return status;
    }

    // Open Transport Mutex
    InitializeObjectAttributes(&objAttributes, &transportMutexPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = NtOpenMutant(&transportMutex, ((0x000F0000L) | (0x00100000L) | 0x0001), &objAttributes);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to open Transport mutex: 0x%08X\n", status);
        return status;
    }

    // Open Application Mutex
    InitializeObjectAttributes(&objAttributes, &applicationMutexPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = NtOpenMutant(&applicationMutex, ((0x000F0000L) | (0x00100000L) | 0x0001), &objAttributes);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to open Application mutex: 0x%08X\n", status);
        return status;
    }

    return STATUS_SUCCESS;
}

VOID UnInitMutexes()
{
    if (ethernetMutex) NtClose(ethernetMutex);
    if (internetMutex) NtClose(internetMutex);
    if (transportMutex) NtClose(transportMutex);
    if (applicationMutex) NtClose(applicationMutex);
}