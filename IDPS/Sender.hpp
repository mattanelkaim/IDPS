#pragma once

// Do NOT sort these includes
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <IcmpAPI.h>
#include <vector>
#include <iostream>
#include <thread>

// Link with Ws2_32.lib and Iphlpapi.lib (for GetAdaptersInfo)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace Sender
{
    bool GetLocalIpAddress(const char* interfaceName, PIP_ADDR_STRING localIP)
    {
        ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO); // Cannot be const because GetAdaptersInfo changes it
        PIP_ADAPTER_INFO AdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(malloc(ulOutBufLen));
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
            AdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(malloc(ulOutBufLen));
            if (AdapterInfo == NULL) [[unlikely]]
            {
                perror("Error allocating memory needed to call GetAdaptersInfo");
                return false;
            }
        }
        
        puts("------ Available adapters ------");
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
                    memcpy(localIP, &pAdapterInfo->IpAddressList, sizeof(IP_ADDR_STRING));
                    localIP->Next = nullptr;
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


    mac SendARPRequest(const in_addr target)
    {
        // Prepare the ARP request structure
        mac macAddress;
        ULONG macAddressLen = sizeof(macAddress); // Cannot be const (SendARP changes it)

        // Send the ARP request
        if (SendARP(target.s_addr, INADDR_ANY, macAddress.bytes, &macAddressLen) != NO_ERROR)
            perror("Error sending ARP request.");

        return macAddress;
    }


    bool SendPing(const in_addr target)
    {
        // Create the ICMP context.
        HANDLE icmpHandle = IcmpCreateFile();
        if (icmpHandle == INVALID_HANDLE_VALUE)
        {
            perror("Error creating ICMP handle.");
            return false;
        }

        // Payload to send.
        constexpr WORD payloadSize = 1;
        unsigned char payload[payloadSize]{0};

        // Reply buffer for exactly 1 echo reply, payload data, and 8 bytes for ICMP error message.
        constexpr DWORD replyBufSize = sizeof(ICMP_ECHO_REPLY) + payloadSize + 8;
        unsigned char replyBuffer[replyBufSize]{0};

        constexpr DWORD timeout = 10'000; // 10 seconds

        const DWORD replyCount = IcmpSendEcho(icmpHandle, ntohl(target.s_addr), payload, payloadSize, NULL, replyBuffer, replyBufSize, timeout);

        if (replyCount == 0)
        {
            //std::cerr << "Error sending ICMP echo request: " << GetLastError() << '\n';
            IcmpCloseHandle(icmpHandle);
            return false;
        }


        IcmpCloseHandle(icmpHandle);
        const ICMP_ECHO_REPLY reply = *reinterpret_cast<ICMP_ECHO_REPLY*>(replyBuffer);
        return reply.Status == IP_SUCCESS;
    }

    std::vector<in_addr> mapLocalNetwork(const IP_ADDR_STRING& localIpData)
    {
        const auto maxAddr = Helper::getBroadcastAddress<ULONG>(localIpData);
        in_addr currAddr{};
        currAddr.s_addr = Helper::getMinAddress(localIpData);

        std::vector<in_addr> onlineAddresses;
        std::vector<std::thread> threads;

        for (currAddr; currAddr.s_addr < maxAddr; ++currAddr.s_addr)
        {
            threads.push_back(std::thread([&onlineAddresses, currAddr]() {
                if (SendPing(currAddr)) onlineAddresses.push_back(currAddr);
            }));
        }

        // Wait for all threads to finish
        for (auto& thread : threads)
            thread.join();

        // Remove self from online vector
        //const ULONG selfAddr = Helper::ipToLong(localIpData.IpAddress.String);
        return onlineAddresses;
    }
}; // namespace Sender
