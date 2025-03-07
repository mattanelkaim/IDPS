// Do NOT sort these includes
#include "json.hpp"
#include "Sender.h"
#include <iphlpapi.h>
#include <IcmpAPI.h>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <iostream>

using json = nlohmann::json;


bool Sender::GetLocalIpAddress(const char* interfaceName, PIP_ADDR_STRING localIP) noexcept
{
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO); // Cannot be const because GetAdaptersInfo changes it
    PIP_ADAPTER_INFO AdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(malloc(ulOutBufLen));
    if (AdapterInfo == NULL) [[unlikely]]
    {
        std::cerr << "Error allocating memory needed to call GetAdaptersInfo\n";
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
            std::cerr << "Error allocating memory needed to call GetAdaptersInfo\n";
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


mac Sender::SendARPRequest(in_addr target) noexcept
{
    // Prepare the ARP request structure
    mac macAddress;
    ULONG macAddressLen = sizeof(macAddress); // Cannot be const (SendARP changes it)

    // Send the ARP request
    if (SendARP(ntohl(target.s_addr), INADDR_ANY, macAddress.bytes, &macAddressLen) != NO_ERROR)
        puts("Error sending ARP request");

    return macAddress;
}

bool Sender::SendPing(in_addr target) noexcept
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
    std::vector<std::jthread> threads;

    for (; currAddr.s_addr < maxAddr; ++currAddr.s_addr)
    {
        threads.push_back(std::jthread([&onlineAddresses, currAddr]() {
            if (SendPing(currAddr)) onlineAddresses.push_back(currAddr);
        }));
    }

    return onlineAddresses;
}

std::string Sender::DoHQuery(std::string_view domain) 
{
    // Cloudflare's DoH endpoint details
    constexpr std::wstring_view server = L"cloudflare-dns.com";
    const std::wstring wsDomain(std::from_range, domain);
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

    return response;
}

void Sender::sendDNSResponse(const Packet& dnsQuery)
{
    // First get the DoH response
    const std::string& question = static_cast<DNSMessage*>(dnsQuery.applicationData)->questions.front();
    const std::string dohResponse = DoHQuery(question);

    // Then write the response OVER the original DNS query
    DNSMessage* responseDNS = static_cast<DNSMessage*>(dnsQuery.applicationData);
    responseDNS->answers = extractDNSRecordsFromJson(dohResponse, "Answer");
    responseDNS->authorities = extractDNSRecordsFromJson(dohResponse, "Authority");
    responseDNS->additionalRecords = extractDNSRecordsFromJson(dohResponse, "Additional");

    constructDNSPayload(*responseDNS);

    // Construct the response header (swap all bytes back to little endian)
    DNSHeader& header = responseDNS->header; // For convenience
    header.transactionID = Helper::byteswap(header.transactionID);
    header.flags = Helper::byteswap(0x8180Ui16); // Set the flags to indicate a response
    header.questionCount = Helper::byteswap(header.questionCount);
    header.answerCount = Helper::byteswap(static_cast<uint16_t>(responseDNS->answers.size()));
    header.authorityCount = Helper::byteswap(static_cast<uint16_t>(responseDNS->authorities.size()));
    header.additionalCount = Helper::byteswap(static_cast<uint16_t>(responseDNS->additionalRecords.size()));

    // Insert the header and payload to the response buffer
    std::vector<char> response(std::from_range, std::span{reinterpret_cast<char*>(&responseDNS->header), sizeof(responseDNS->header)});
    response.append_range(constructDNSPayload(*responseDNS));


    // Open a socket to send the response (and bind it to port 53)
    SOCKET sendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    constexpr sockaddr_in socketAddr = Helper::getLocalhostDnsAddr();
    bind(sendSocket, reinterpret_cast<const sockaddr*>(&socketAddr), sizeof(socketAddr));

    sockaddr_in clientAddr = Helper::getLocalhostDnsAddr();
    clientAddr.sin_port = std::byteswap(dnsQuery.transportHeader->srcPort); // Send the response to the source port
    
    // Send the response
    int sendResult = sendto(sendSocket,
                            response.data(),
                            static_cast<int>(response.size()),
                            0, // Reserve or some shit
                            reinterpret_cast<const sockaddr*>(&clientAddr),
                            sizeof(clientAddr));

    closesocket(sendSocket); // Not RAII because no exceptions can be thrown since socket creation
}

std::vector<uint8_t> Sender::constructDNSPayload(const DNSMessage& message)
{
    std::vector<uint8_t> payload;
    const std::string& query = message.questions.front();
    
    // Append the question (interpret string as pure bytes)
    payload.append_range(DNSMessage::deserializeDomainName({reinterpret_cast<const uint8_t*>(query.data()), query.size()}));
    // Append type A and class IN
    payload.insert(payload.end(), {0x00, 0x01, 0x00, 0x01});

    // Extract offsets for each name in the response
    std::unordered_map<std::string, uint16_t> nameOffsets;
    uint16_t lastOffset = sizeof(DNSHeader);
    nameOffsets.emplace(query, lastOffset); // Query domain

    // First response record has a different offset:
    // 16 (fields lengths) + 2 (null and first dot) + query.size()
    lastOffset += static_cast<uint16_t>(18 + query.size());

    for (const DNSRecord& record : message.answers)
    {
        // Offset is 14-bits long, so we need to split it into 2 bytes
        const uint16_t current = nameOffsets.at(std::get<std::string>(record.name));
        payload.push_back((current >> 12) | 0b11000000); // First 2 bits are set
        payload.push_back(current & 0xFF);

        Helper::insertWordToBytes(payload, record.type);
        Helper::insertWordToBytes(payload, record.recordClass);
        Helper::insertDwordToBytes(payload, record.ttl);

        if (record.type == DNSTypes::A) // IPv4 address
        {
            // Length is 4 (IPv4 address)
            Helper::insertWordToBytes(payload, 4);

            // Currently data stores IP as 1 byte for each digit. Use helper so that each byte will represent an IP byte
            const in_addr ip = Helper::strToIp(std::string(std::from_range, record.data));
            Helper::insertDwordToBytes(payload, ip.s_addr);
        }
        else if (record.type == DNSTypes::CNAME) // Canonical name
        {
            // Deserialize domain and append its length and data to the payload
            std::vector<uint8_t> domain = DNSMessage::deserializeDomainName(record.data);
            Helper::insertWordToBytes(payload, static_cast<uint16_t>(domain.size()));
            payload.append_range(std::move(domain));

            // Update the name with its offset
            nameOffsets.emplace(std::string(std::from_range, record.data), lastOffset);
        }
        else // Unsupported type (very unlikely)
        {
            throw std::runtime_error("Unsupported DNS record type");
        }

        // 12 (fields lengths) + 2 (null and first dot) + name.size()
        lastOffset += 14 + static_cast<uint16_t>(record.data.size());
    }

    return payload;
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
                // Handle cases where the data ends with a dot (for some reason)
                std::string data = entry["data"].get<std::string>();
                if (data.back() == '.')
                    data.pop_back();

                records.emplace_back(
                    entry["name"].get<std::string>(),
                    entry["type"].get<uint16_t>(),
                    entry["TTL"].get<uint32_t>(),
                    std::move(data)
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
    if (m_handle) // Function expects a valid handle
        WinHttpCloseHandle(m_handle);
}

constexpr WinHttpHandle::operator HINTERNET() const noexcept
{
    return m_handle;
}
