#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace Sender
{
    bool GetBroadcastAddress(const char* interfaceName, in_addr& broadcast)
    {
        ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO); // Cannot be const
        PIP_ADAPTER_INFO AdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        if (AdapterInfo == NULL)
        {
            printf("Error allocating memory needed to call GetAdaptersInfo\n");
            return false;
        }

        // Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
        if (GetAdaptersInfo(AdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
        {
            // Re-allocate the memory and try again (ulOutBufLen now has the correct size)
            free(AdapterInfo);
            AdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
            if (AdapterInfo == NULL)
            {
                printf("Error allocating memory needed to call GetAdaptersInfo\n");
                return false;
            }
        }
        
        // Call function again with the correct buffer size
        if (GetAdaptersInfo(AdapterInfo, &ulOutBufLen) == NO_ERROR)
        {
            PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo; // Temp pointer to iterate over the list
            while (pAdapterInfo)
            {
                printf("%s: %s\n", pAdapterInfo->Description, pAdapterInfo->IpAddressList.IpAddress.String);
                if (strcmp(pAdapterInfo->Description, interfaceName) == 0)
                {
                    inet_pton(AF_INET, pAdapterInfo->IpAddressList.IpAddress.String, &broadcast);
                    broadcast.s_impno = 255;
                    return true;
                }

                pAdapterInfo = pAdapterInfo->Next; // Else move to the next adapter
            }
        }
        else
            printf("Call to GetAdaptersInfo failed.\n");

        free(AdapterInfo);
        return false;
    }
}; // namespace Sender
