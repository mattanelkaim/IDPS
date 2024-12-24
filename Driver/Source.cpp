// do NOT change order of includation
#include "LayerHandles.h"
#include <ntifs.h>
#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#define INITGUID
#include <guiddef.h>
#include <fwpmu.h>

// Helper Definitions
#define __IGNORE [[maybe_unused]]
#define SIGNATURE "##-IDPS_SNIFFER-##: "
#define IDPS_PRINT(x) KdPrint((SIGNATURE x)) // x is a literal string
#define IDPS_PRINT2(x1, x2) KdPrint((SIGNATURE x1, x2)) // x1 is a literal string, x2 is a string (char*)
#define IDPS_PRINT3(x1, x2, x3) KdPrint((SIGNATURE x1, x2, x3)) // x1 is a literal string, x2 is the buffer length, x3 is the char buffer
#define IDPS_PRINT4(x1, x2, x3, x4) KdPrint((SIGNATURE x1, x2, x3, x4)) // 4 params

// work item to operate at IRQL passive level
typedef struct _WORK_CONTEXT {
    char WorkItem[128]; // A 128 byte buffer to replace _IO_WORKITEM (128 is based purely on hope and prayer)
    BOOL queued;
    BOOL ongoing;
	BOOL held;
	BYTE layerData[65536]; // 64KB buffer to store the layer data
	USHORT layerDataLength;
} WORK_CONTEXT, * PWORK_CONTEXT;

WORK_CONTEXT workContext = { 0 };
BOOL driverUnloading = FALSE;

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
#define ETHERNET_FILE_PATH (BASE_FILE_DIRECTORY L"ethernet.bin")
#define INTERNET_FILE_PATH (BASE_FILE_DIRECTORY L"internet.bin")
#define TRANSPORT_FILE_PATH (BASE_FILE_DIRECTORY L"transport.bin")
#define APPLICATION_FILE_PATH (BASE_FILE_DIRECTORY L"application.bin")

PDEVICE_OBJECT deviceObject = NULL;
HANDLE engineHandle = NULL;
UINT32 EthernetRegCalloutId = 0, IpRegCalloutId = 0, TransportRegCalloutId = 0, ApplicationRegCalloutId = 0;
UINT32 EthernetAddCalloutId = 0, IpAddCalloutId = 0, TransportAddCalloutId = 0, ApplicationAddCalloutId = 0;
UINT64 EthernetFilterId = 0, IpFilterId = 0, TransportFilterId = 0, ApplicationFilterId = 0;
HANDLES mutexes = { NULL, NULL, NULL, NULL };
HANDLE workMutex = NULL;
KERNEL_OBJECTS kernelMutexObjects = { NULL, NULL, NULL, NULL };

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
void writeToFile(PUNICODE_STRING filePath, PVOID buffer, ULONG bufferSize);
void TryQueueWorkItem(PVOID layerData);
NTSTATUS InitFileNames();
VOID UnInitMutexes();
IO_WORKITEM_ROUTINE WorkItemRoutine;
void copyLayerData(PVOID layerData);

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
    IDPS_PRINT("Driver unloaded succefully!\n");
}

// Handling function
NTSTATUS DriverPassThru(__IGNORE PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    PHANDLES userHandles = NULL;  // Pointer to the user-provided structure
    PEPROCESS sourceProcessHandle;
    OBJECT_ATTRIBUTES objAttrs;
    CLIENT_ID clientId;

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
    case IRP_MJ_DEVICE_CONTROL:
        if (IOCTL_SEND_HANDLES != irpSp->Parameters.DeviceIoControl.IoControlCode)
        {
            IDPS_PRINT("Recevied invalid ioctl request");
            break;
        }

        IDPS_PRINT("Received handles!\n");
        if (IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.InputBufferLength < sizeof(IOCTL_HANDLES)) {
            IDPS_PRINT("Recevied invalid IOCTL struct");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        // Get the input buffer from the IRP
        userHandles = &(((PIOCTL_HANDLES)Irp->AssociatedIrp.SystemBuffer)->mutexes);

        //PsLookupProcessByProcessId((HANDLE)((PIOCTL_HANDLES)Irp->AssociatedIrp.SystemBuffer)->pid, &sourceProcessHandle);
        clientId.UniqueProcess = (HANDLE)((PIOCTL_HANDLES)Irp->AssociatedIrp.SystemBuffer)->pid;  // PID of the source process
        clientId.UniqueThread = 0;

        InitializeObjectAttributes(&objAttrs, NULL, 0, NULL, NULL);

        status = ZwOpenProcess( &sourceProcessHandle, PROCESS_DUP_HANDLE, &objAttrs, &clientId);
        if (!NT_SUCCESS(status))
        {
            IDPS_PRINT("ZwOpenProcess failed!");
            break;
        }
        IDPS_PRINT("Opened parent process succefully");

        BOOLEAN duplicatedSuccefully = TRUE;
        for (int i = 0; i < (sizeof(HANDLES)/sizeof(HANDLE)); i++) {
            ((HANDLE*)&mutexes)[i] = ((HANDLE*)userHandles)[i];  // Access handles dynamically

            status = ZwDuplicateObject(sourceProcessHandle, ((HANDLE*)userHandles)[i], NtCurrentProcess(), (((HANDLE*)&mutexes) + i), SYNCHRONIZE, 0, 0);
            if (!NT_SUCCESS(status))
            {
                IDPS_PRINT3("Error duplicating handle %d : %X", i, status);
                duplicatedSuccefully = FALSE;
                break;
            }
        }

        if (!duplicatedSuccefully)
            break;

        IDPS_PRINT("Succesfully duplicated handles");

        IDPS_PRINT("Initializing WFP...\n");

        status = InitializeWfp();
        if (!NT_SUCCESS(status))
        {
            // InitializeWfp() already prints err and calls UnInitWfp()
            IoDeleteDevice(deviceObject);
            IoDeleteSymbolicLink(&SYMLINK_NAME);
            return status;
        }


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

    //callout.calloutKey = ETHERNET_CALLOUT_GUID;
    //callout.applicableLayer = FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET; // Ethernet Layer
    //status = FwpmCalloutAdd(engineHandle, &callout, NULL, &EthernetAddCalloutId);
    //if (!NT_SUCCESS(status))
    //    return status;

    callout.calloutKey = IP_CALLOUT_GUID;
    callout.applicableLayer = FWPM_LAYER_INBOUND_IPPACKET_V4; // Ip Layer
    status = FwpmCalloutAdd(engineHandle, &callout, NULL, &IpAddCalloutId);
    if (!NT_SUCCESS(status))
        return status;

    //callout.calloutKey = TRANSPORT_CALLOUT_GUID;
    //callout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4; // Transport Layer
    //status = FwpmCalloutAdd(engineHandle, &callout, NULL, &TransportAddCalloutId);
    //if (!NT_SUCCESS(status))
    //    return status;

    //callout.calloutKey = APPLICATION_CALLOUT_GUID;
    //callout.applicableLayer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4; // Application Layer
    //status = FwpmCalloutAdd(engineHandle, &callout, NULL, &ApplicationAddCalloutId);
    //if (!NT_SUCCESS(status))
    //    return status;

    return status;
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

    /*sublayer.subLayerKey = ETHERNET_SUBLAYER_GUID;
    status = FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status))
        return status;*/

    sublayer.subLayerKey = IP_SUBLAYER_GUID;
    status = FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status))
        return status;

    /*sublayer.subLayerKey = TRANSPORT_SUBLAYER_GUID;
    status = FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status))
        return status;*/

    /*sublayer.subLayerKey = APPLICATION_SUBLAYER_GUID;
    status = FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status))
        return status;*/

    return status;
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

    //filter.subLayerKey = ETHERNET_SUBLAYER_GUID;
    //filter.action.calloutKey = ETHERNET_CALLOUT_GUID;
    //filter.layerKey = FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET; // Ethernet Layer
    //status = FwpmFilterAdd(engineHandle, &filter, NULL, &EthernetFilterId);
    //if (!NT_SUCCESS(status))
    //    return status;

    filter.subLayerKey = IP_SUBLAYER_GUID;
    filter.action.calloutKey = IP_CALLOUT_GUID;
    filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4; // Ip Layer
    status = FwpmFilterAdd(engineHandle, &filter, NULL, &IpFilterId);
    if (!NT_SUCCESS(status))
        return status;

    //filter.subLayerKey = TRANSPORT_SUBLAYER_GUID;
    //filter.action.calloutKey = TRANSPORT_CALLOUT_GUID;
    //filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4; // Transport Layer
    //status = FwpmFilterAdd(engineHandle, &filter, NULL, &TransportFilterId);
    //if (!NT_SUCCESS(status))
    //    return status;

    //filter.subLayerKey = APPLICATION_SUBLAYER_GUID;
    //filter.action.calloutKey = APPLICATION_CALLOUT_GUID;
    //filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4; // Application Layer
    //status = FwpmFilterAdd(engineHandle, &filter, NULL, &ApplicationFilterId);
    //if (!NT_SUCCESS(status))
    //    return status;

    return status;
}

NTSTATUS WfpRegisterCallout()
{
    NTSTATUS status;
    IDPS_PRINT("Registering callout...\n");
    FWPS_CALLOUT callout = { 0 };
    callout.flags = 0;
    callout.notifyFn = NotifyCallback;
    callout.flowDeleteFn = FlowDeleteCallback;

    /*callout.calloutKey = ETHERNET_CALLOUT_GUID;
    callout.classifyFn = EthernetCallback;
    status =  FwpsCalloutRegister(deviceObject, &callout, &EthernetRegCalloutId);
    if (!NT_SUCCESS(status))
        return status;*/

    callout.calloutKey = IP_CALLOUT_GUID;
    callout.classifyFn = IpCallback;
    status = FwpsCalloutRegister(deviceObject, &callout, &IpRegCalloutId);
    if (!NT_SUCCESS(status))
        return status;

    /*callout.calloutKey = TRANSPORT_CALLOUT_GUID;
    callout.classifyFn = TransportCallback;
    status = FwpsCalloutRegister(deviceObject, &callout, &TransportRegCalloutId);
    if (!NT_SUCCESS(status))
        return status;*/

    /*callout.calloutKey = APPLICATION_CALLOUT_GUID;
    callout.classifyFn = ApplicationCallback;
    status = FwpsCalloutRegister(deviceObject, &callout, &ApplicationRegCalloutId);
    if (!NT_SUCCESS(status))
        return status;*/

    return status;
}

VOID EthernetCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
{
    IDPS_PRINT("Received inbound Ethernet packet");

    if (layerData == NULL || classifyOut == NULL) {
        IDPS_PRINT("Layer data or classifyOut is NULL");
        return;
    }

    IDPS_PRINT("Layer data is not null");

    RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));
    classifyOut->actionType = FWP_ACTION_PERMIT;

    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;
    if (nbl == NULL) {
        IDPS_PRINT("NET_BUFFER_LIST is NULL");
        return;
    }

    IDPS_PRINT("NET_BUFFER_LIST is not null");

    NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    while (nb != NULL) {
        ULONG packetLength = NET_BUFFER_DATA_LENGTH(nb);

        // Ensure buffer to read data
        UCHAR packetBuffer[1024] = { 0 };
        ULONG readLength = (packetLength < sizeof(packetBuffer)) ? packetLength : sizeof(packetBuffer);

        // Retrieve the data
        PUCHAR data = NdisGetDataBuffer(nb, readLength, packetBuffer, 1, 0);
        if (data == NULL) {
            IDPS_PRINT("Failed to retrieve packet data");
            return;
        }

        // If data was mapped into the local buffer, update pointer to it
        if (data != packetBuffer) {
            RtlCopyMemory(packetBuffer, data, readLength);
        }

        // Print the raw data as a string (may include non-printable characters)
        ULONG i = 0;
        for (i = 0; i + 64ul < readLength; i += 64)
            IDPS_PRINT3("%.*s", i, packetBuffer + i);
        IDPS_PRINT3("%.*s", readLength - i, packetBuffer + i);
        //IDPS_PRINT("waiting for mutex");
        //if (!NT_SUCCESS(KeWaitForSingleObject(mutexes.internet, Executive, KernelMode, FALSE, NULL)))
        //{
        //    IDPS_PRINT("Failed to wait for mutex");
        //}
        ///*IDPS_PRINT("writing buffer to file");
        //WriteToFile(&internetFilePath, packetBuffer, readLength);*/
        //IDPS_PRINT("Releasing mutex");
        //KeReleaseMutex(mutexes.internet, FALSE);

        // Move to the next NET_BUFFER
        nb = NET_BUFFER_NEXT_NB(nb);
    }

    IDPS_PRINT("Finished processing packet");
}
VOID IpCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
{
    IDPS_PRINT("Received inbound IP packet...");

    if (layerData == NULL || classifyOut == NULL) {
        IDPS_PRINT("Layer data or classifyOut is NULL");
        return;
    }

    RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));
    classifyOut->actionType = FWP_ACTION_PERMIT;
        
    IDPS_PRINT("queueing work item");
    TryQueueWorkItem(layerData);
}
VOID TransportCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
{
    IDPS_PRINT("Received inbound IP packet");

    if (layerData == NULL || classifyOut == NULL) {
        IDPS_PRINT("Layer data or classifyOut is NULL");
        return;
    }

    IDPS_PRINT("Layer data is not null");

    RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));
    classifyOut->actionType = FWP_ACTION_PERMIT;

    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;
    if (nbl == NULL) {
        IDPS_PRINT("NET_BUFFER_LIST is NULL");
        return;
    }

    IDPS_PRINT("NET_BUFFER_LIST is not null");

    NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    while (nb != NULL) {
        ULONG packetLength = NET_BUFFER_DATA_LENGTH(nb);

        // Ensure buffer to read data
        UCHAR packetBuffer[1024] = { 0 };
        ULONG readLength = (packetLength < sizeof(packetBuffer)) ? packetLength : sizeof(packetBuffer);

        // Retrieve the data
        PUCHAR data = NdisGetDataBuffer(nb, readLength, packetBuffer, 1, 0);
        if (data == NULL) {
            IDPS_PRINT("Failed to retrieve packet data");
            return;
        }

        // If data was mapped into the local buffer, update pointer to it
        if (data != packetBuffer) {
            RtlCopyMemory(packetBuffer, data, readLength);
        }

        // Print the raw data as a string (may include non-printable characters)
        IDPS_PRINT3("%.*s", readLength, packetBuffer);
        //IDPS_PRINT("waiting for mutex");
        //if (!NT_SUCCESS(KeWaitForSingleObject(mutexes.internet, Executive, KernelMode, FALSE, NULL)))
        //{
        //    IDPS_PRINT("Failed to wait for mutex");
        //}
        ///*IDPS_PRINT("writing buffer to file");
        //WriteToFile(&internetFilePath, packetBuffer, readLength);*/
        //IDPS_PRINT("Releasing mutex");
        //KeReleaseMutex(mutexes.internet, FALSE);

        // Move to the next NET_BUFFER
        nb = NET_BUFFER_NEXT_NB(nb);
    }

    IDPS_PRINT("Finished processing packet");
}
VOID ApplicationCallback(__IGNORE const FWPS_INCOMING_VALUES0* inFixedValues, __IGNORE const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, __IGNORE const void* context, __IGNORE const FWPS_FILTER* filter, __IGNORE UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut)
{
    RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));

    FWPS_STREAM_CALLOUT_IO_PACKET* packet = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerData;
    
    IDPS_PRINT("Received application packet");
    FWPS_STREAM_DATA0* streamData = packet->streamData;
    UCHAR string[1024] = { 0 };
    SIZE_T length = 0;
    SIZE_T bytes;

    if ((streamData->flags & FWPS_STREAM_FLAG_RECEIVE))
    {
        length = streamData->dataLength <= 1024 ? streamData->dataLength : 1024; // only reading 1024 bytes from the stream (or less)
        FwpsCopyStreamDataToBuffer(streamData, string, length, &bytes);
        IDPS_PRINT2("data is %s\r\n", string);
    }
    
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

VOID UnInitWfp()
{
#define delFilter(x) if (x) {FwpmFilterDeleteById(engineHandle, x);}
#define delCallout(x) if (x) {FwpmCalloutDeleteById(engineHandle, x);}
#define unregCallout(x) if (x) {FwpsCalloutUnregisterById(x);}
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

    UnInitMutexes();
}
void writeToFile(PUNICODE_STRING filePath, PVOID buffer, ULONG bufferSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objAttributes;
    IO_STATUS_BLOCK ioStatusBlock;

    if (!buffer)
    {
        IDPS_PRINT("writeToFile received null buffer");
        return;
    }

    // Initialize the OBJECT_ATTRIBUTES structure
    IDPS_PRINT("Initializing file attributes");
    InitializeObjectAttributes(
        &objAttributes,
        filePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    // Open or create the file
    IDPS_PRINT("Creating file handle");
    status = ZwCreateFile(
        &fileHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        IDPS_PRINT2("Failed to open file: %x", status);
        goto closeFile;
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

    if (!NT_SUCCESS(status)) {
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

void TryQueueWorkItem(PVOID layerData)
{
    if (!workContext.ongoing)
    {
		workContext.held = TRUE;
		copyLayerData(layerData);
		workContext.held = FALSE;
    }

    if (workContext.queued || driverUnloading)
    {
        IDPS_PRINT("Work item already queued...");
        return;
    }

    workContext.queued = TRUE;

    // Queue the work item
    IoQueueWorkItem(
        (PIO_WORKITEM)&workContext.WorkItem,
        WorkItemRoutine,
        DelayedWorkQueue,
        &workContext
    );

    IDPS_PRINT("Work item queued succefully!");
}

NTSTATUS InitFileNames()
{
    IDPS_PRINT("Initializing file names");

    RtlInitUnicodeString(&ethernetFilePath, ETHERNET_FILE_PATH);
    RtlInitUnicodeString(&internetFilePath, INTERNET_FILE_PATH);
    RtlInitUnicodeString(&transportFilePath, TRANSPORT_FILE_PATH);
    RtlInitUnicodeString(&applicationFilePath, APPLICATION_FILE_PATH);
    RtlInitUnicodeString(&ethernetMutexPath, ETHERNET_MUTEX_PATH);
    RtlInitUnicodeString(&internetMutexPath, INTERNET_MUTEX_PATH);
    RtlInitUnicodeString(&transportMutexPath, TRANSPORT_MUTEX_PATH);
    RtlInitUnicodeString(&applicationMutexPath, APPLICATION_MUTEX_PATH);

    return STATUS_SUCCESS;
}

VOID UnInitMutexes()
{
    ZwClose(mutexes.ethernet);
    ZwClose(mutexes.internet);
    ZwClose(mutexes.transport);
    ZwClose(mutexes.application);
}

void copyLayerData(PVOID layerData)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNET_BUFFER_LIST netBufferList = (PNET_BUFFER_LIST)layerData;
    PNET_BUFFER netBuffer = NULL;
    USHORT totalDataLength = 0; // To store the full packet length as 8 bytes
	USHORT currPos = 0; // Current position in the buffer

	if (!layerData)
		return;
	
    // Calculate the total length of data in the Net Buffer List
    netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    while (netBuffer != NULL) {
        totalDataLength += (USHORT)NET_BUFFER_DATA_LENGTH(netBuffer);
        netBuffer = NET_BUFFER_NEXT_NB(netBuffer);
    }

	workContext.layerDataLength = totalDataLength;

    if (totalDataLength == 0)
    {
        IDPS_PRINT("Work item received no data!");
        return; // Nothing to write
    }


    // Traverse each NET_BUFFER in the NET_BUFFER_LIST again to write the actual data
    netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    while (netBuffer != NULL) {
        ULONG dataLength = NET_BUFFER_DATA_LENGTH(netBuffer);
        PVOID dataPointer = NULL;
        PMDL mdl = NET_BUFFER_FIRST_MDL(netBuffer);
        ULONG offset = NET_BUFFER_CURRENT_MDL_OFFSET(netBuffer);

        // Traverse the MDL chain for this NET_BUFFER
        while (mdl != NULL && dataLength > 0) {
            ULONG mdlLength = MmGetMdlByteCount(mdl) - offset;
            ULONG bytesToProcess = min(dataLength, mdlLength);

            // Map the MDL to a virtual address
            dataPointer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            if (dataPointer == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            // Adjust the pointer for the offset
            dataPointer = (PVOID)((PUCHAR)dataPointer + offset);

            // Write this chunk of data to the file
			RtlCopyMemory(workContext.layerData + currPos, dataPointer, bytesToProcess);
			currPos += (USHORT)bytesToProcess;

            // Update the remaining data length and move to the next MDL
            dataLength -= (USHORT)bytesToProcess;
            offset = 0; // Offset is only applicable to the first MDL
            mdl = mdl->Next;
        }

        if (!NT_SUCCESS(status)) {
            break;
        }

        // Move to the next NET_BUFFER in the list
        netBuffer = NET_BUFFER_NEXT_NB(netBuffer);
    }
}

VOID WorkItemRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PWORK_CONTEXT context = (PWORK_CONTEXT)Context;

	if (!context)
	{
		IDPS_PRINT("Work item routine received null context");
		return;
	}

    context->ongoing = TRUE;
	while (context->held) {} // waiting for the work item to be released

    // If the driver unloaded while the work item was still queued
    if (driverUnloading || !context->layerData)
    {
        IDPS_PRINT("Abandoning work item routine");
        context->ongoing = FALSE;
        return;
    }

    IDPS_PRINT("Begun work item routine!");

    // Write the total length (8 bytes) to the file
    writeToFile(&internetFilePath, &workContext.layerDataLength, sizeof(workContext.layerDataLength));

	// writing the actual data to the file
    USHORT i;
    for (i = 0; i + 64 < workContext.layerDataLength; i += 64)
        IDPS_PRINT3("%.*s", 64, workContext.layerData + i);
    IDPS_PRINT3("%.*s", workContext.layerDataLength - i, workContext.layerData + i);
    writeToFile(&internetFilePath, workContext.layerData, workContext.layerDataLength);

    context->queued = FALSE;
    context->ongoing = FALSE;
    IDPS_PRINT("Finished work item routine");
}