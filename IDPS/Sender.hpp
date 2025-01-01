#pragma once

// Do NOT sort these includes
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

// Link with Ws2_32.lib and Iphlpapi.lib (for GetAdaptersInfo)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace Sender
{
    bool GetBroadcastAddress(const char* interfaceName, in_addr& broadcast)
    {
        ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO); // Cannot be const because GetAdaptersInfo changes it
        PIP_ADAPTER_INFO AdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        if (AdapterInfo == NULL) [[unlikely]]
        {
            perror("Error allocating memory needed to call GetAdaptersInfo");
            return false;
        }

        // Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
        if (GetAdaptersInfo(AdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
        {
            // Re-allocate the memory and try again (ulOutBufLen now has the correct size)
            free(AdapterInfo);
            AdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
            if (AdapterInfo == NULL) [[unlikely]]
            {
                perror("Error allocating memory needed to call GetAdaptersInfo");
                return false;
            }
        }
        
        // Call function again with the correct buffer size
        if (GetAdaptersInfo(AdapterInfo, &ulOutBufLen) == NO_ERROR) [[likely]]
        {
            // Iterate over the list of adapters until target adapter is found
            PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo; // Temp pointer to iterate over the list
            while (pAdapterInfo)
            {
                printf("%s: %s\n", pAdapterInfo->Description, pAdapterInfo->IpAddressList.IpAddress.String); // TEMP FOR DEBUGGING
                if (strcmp(pAdapterInfo->Description, interfaceName) == 0)
                {
                    // Convert string to in_addr and change last byte to 255
                    inet_pton(AF_INET, pAdapterInfo->IpAddressList.IpAddress.String, &broadcast);
                    broadcast.s_impno = 255;
                    free(AdapterInfo);
                    return true;
                }

                pAdapterInfo = pAdapterInfo->Next; // Else move to the next adapter
            }
        }
        else [[unlikely]]
        {
            perror("Call to GetAdaptersInfo failed.");
        }

        free(AdapterInfo);
        return false;
    }
}; // namespace Sender
