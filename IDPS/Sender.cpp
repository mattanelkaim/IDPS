// Do NOT sort these includes
#include "json.hpp"
#include "Sender.h"
#include <iphlpapi.h>
#include <IcmpAPI.h>
#include <stdexcept>
#include <thread>

using json = nlohmann::json;


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

std::vector<DNSRecord> Sender::DoHQuery(const std::string& domain) 
{
    // Cloudflare's DoH endpoint details
    constexpr std::wstring_view server = L"cloudflare-dns.com";
    const std::wstring wsDomain(domain.begin(), domain.end());
    const std::wstring path = L"/dns-query?name=" + wsDomain + L"&type=A"; // Type A is IPv4 resolve

    // Open a WinHTTP session with a custom user-agent
    WinHttpHandle session(WinHttpOpen(L"C++DoHClient/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    // Connect to the server
    WinHttpHandle connect(WinHttpConnect(session, server.data(), INTERNET_DEFAULT_HTTPS_PORT, 0));
    
    // Create a secure GET request
    WinHttpHandle request(WinHttpOpenRequest(connect, NULL, path.c_str(), NULL, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    
    // Send the request with an Accept header for a JSON response
    constexpr std::wstring_view acceptHeader = L"Accept: application/dns-json\r\n";
    constexpr ULONG headerSize = static_cast<ULONG>(acceptHeader.size()); // To avoid conversion warnings
    if (!WinHttpSendRequest(request, acceptHeader.data(), headerSize, NULL, NULL, 0, 0))
        throw std::runtime_error("WinHttpSendRequest failed!");

    // Wait for the response
    if (!WinHttpReceiveResponse(request, NULL))
        throw std::runtime_error("WinHttpReceiveResponse failed!");

    // Read the response data (in loop in edge-case of large responses)
    std::string response;
    DWORD bytesAvailable = 0;
    while (WinHttpQueryDataAvailable(request, &bytesAvailable) && (bytesAvailable > 0))
    {
        // Using a char vector to store the raw bytes
        std::vector<char> buffer(bytesAvailable);
        DWORD bytesRead = 0;
        if (!WinHttpReadData(request, buffer.data(), bytesAvailable, &bytesRead))
            throw std::runtime_error("WinHttpReadData failed!");

        response.append(buffer.data(), bytesRead);
    }

    //puts(response.c_str()); // TEMP FOR DEBUGGING
    return extractDNSRecordsFromJson(response);
}

bool Sender::sendDNSResponse(const std::string& response)
{
    
    return false;
}

/*
Extracts the data from the JSON response
JSON response example:
{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"walla.co.il","type":1}],"Answer":[{"name":"walla.co.il","type":1,"TTL":300,"data":"34.102.212.0"}]}
*/
std::vector<DNSRecord> Sender::extractDNSRecordsFromJson(std::string_view dohResponse, std::string_view section)
{
    const json parsed = json::parse(dohResponse);
    std::vector<DNSRecord> records;

    if (parsed.contains(section) && parsed[section].is_array())
    {
        for (const auto& entry : parsed[section])
        {
            if (entry.contains("name") && entry.contains("type") && entry.contains("TTL") && entry.contains("data")) [[likely]]
            {
                records.emplace_back(
                    entry["name"].get<std::string>(),
                    entry["type"].get<uint16_t>(),
                    entry["TTL"].get<uint32_t>(),
                    entry["data"].get<std::string>()
                );
            }
        }
    }

    return records;
}


// WinHttpHandle methods


WinHttpHandle::WinHttpHandle(HINTERNET handle) :
    m_handle(handle)
{
    if (!m_handle)
        throw std::runtime_error("Failed to create WinHTTP handle!");
}

WinHttpHandle::~WinHttpHandle() noexcept
{
    if (m_handle)
        WinHttpCloseHandle(m_handle);
}

constexpr WinHttpHandle::operator HINTERNET() const noexcept
{
    return m_handle;
}
