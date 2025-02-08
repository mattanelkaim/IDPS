// Do NOT sort these includes
#include "Sender.h"
#include <iphlpapi.h>
#include <winhttp.h>
#include <IcmpAPI.h>
#include <thread>


bool Sender::GetLocalIpAddress(const char* interfaceName, PIP_ADDR_STRING localIP) noexcept
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
                localIP->Next = nullptr; // Would be a dangling pointer
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


mac Sender::SendARPRequest(const in_addr target) noexcept
{
    // Prepare the ARP request structure
    mac macAddress;
    ULONG macAddressLen = sizeof(macAddress); // Cannot be const (SendARP changes it)

    // Send the ARP request
    if (SendARP(ntohl(target.s_addr), INADDR_ANY, macAddress.bytes, &macAddressLen) != NO_ERROR)
        puts("Error sending ARP request");

    return macAddress;
}


bool Sender::SendPing(const in_addr target) noexcept
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
    ICMP_ECHO_REPLY replyBuffer[replyBufSize]{0};

    constexpr DWORD timeout = 30'000; // 30 seconds

    const DWORD replyCount = IcmpSendEcho(icmpHandle, ntohl(target.s_addr), payload, payloadSize, NULL, replyBuffer, replyBufSize, timeout);

    if (replyCount == 0)
    {
        //std::cerr << "Error sending ICMP echo request: " << GetLastError() << '\n';
        IcmpCloseHandle(icmpHandle);
        return false;
    }

    IcmpCloseHandle(icmpHandle);
    return replyBuffer->Status == IP_SUCCESS;
}


std::vector<in_addr> Sender::mapLocalNetwork(const IP_ADDR_STRING& localIpData)
{
    const auto maxAddr = Helper::getBroadcastAddress<ULONG>(localIpData);
    in_addr currAddr = std::bit_cast<in_addr>(Helper::getMinAddress(localIpData)); // Need to bit_cast because of union

    std::vector<in_addr> onlineAddresses;
    std::vector<std::thread> threads;

    for (; currAddr.s_addr < maxAddr; ++currAddr.s_addr)
    {
        threads.push_back(std::thread([&onlineAddresses, currAddr]() {
            if (SendPing(currAddr)) onlineAddresses.push_back(currAddr);
        }));
    }

    // Wait for all threads to finish
    for (auto& thread : threads)
        thread.join();

    return onlineAddresses;
}

std::string Sender::SendHTTP(const std::string_view& url) 
{
    std::wstring wurl(url.begin(), url.end());  // Convert URL to wstring
    std::wstring host, path;

    // Parse URL (Extract host and path)
    size_t pos = wurl.find(L"//");
    if (pos != std::wstring::npos) wurl = wurl.substr(pos + 2);
    pos = wurl.find(L"/");
    host = (pos == std::wstring::npos) ? wurl : wurl.substr(0, pos);
    path = (pos == std::wstring::npos) ? L"/" : wurl.substr(pos);

    HINTERNET hSession = WinHttpOpen(L"SimpleHTTP/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) 
        return "";

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) 
    {
        WinHttpCloseHandle(hSession);
        return "";
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) 
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::string response;
    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) 
    {
        char buffer[4096];
        DWORD bytesRead = 0;
        while (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) 
        {
            buffer[bytesRead] = '\0';
            response += buffer;
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}