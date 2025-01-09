#include "Packets/Layers.h"
#include "Packets/Packet.h"
#include "Sender.hpp"
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <WinSock2.h>

static std::vector<uint8_t> readFile(const std::string& filename)
{
    // Open raw packet file
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file!\n";
        return {}; // Empty
    }

    // Determine file size
    file.seekg(0, std::ios::end);
    const std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::cout << "File size: " << fileSize << " bytes\n";

    // Read the entire file into the buffer
    std::vector<uint8_t> buffer(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    if (file.fail())
    {
        std::cerr << "Failed to read file contents!\n";
        return {}; // Empty
    }

    return buffer;
}

static void printHexBuffer(const std::vector<uint8_t>& buffer, const size_t first = 0, const size_t second = 0, const size_t third = 0)
{
    size_t i = 0, sectionEnd = first;

    // Read byte by byte and print in a nice hex format
    std::cout << std::hex << std::setfill('0') << "\033[31m"; // Formatting + red color
    for (; i < sectionEnd; ++i)
        std::cout << std::setw(2) << static_cast<int>(buffer[i]) << " ";
    sectionEnd += second;

    // Print second layer
    std::cout << "\033[32m"; // Green color
    for (; i < sectionEnd; ++i)
        std::cout << std::setw(2) << static_cast<int>(buffer[i]) << " ";
    sectionEnd += third;

    // Print second layer
    std::cout << "\033[33m"; // Yellow color
    for (; i < sectionEnd; ++i)
        std::cout << std::setw(2) << static_cast<int>(buffer[i]) << " ";

    // Print the rest
    std::cout << "\033[0m"; // Reset color
    for (; i < buffer.size(); ++i)
        std::cout << std::setw(2) << static_cast<int>(buffer[i]) << " ";

    std::cout << std::dec << '\n';
}


int main()
{
    //const std::vector<uint8_t> rawData = readFile("dns packet.bin");
 
    //printHexBuffer(rawData, sizeof(EthernetHeader), sizeof(IPv4Header), sizeof(UDPHeader));

    //Packet packet(rawData);

    IP_ADDR_STRING localIP;
    if (!Sender::GetLocalIpAddress("Realtek PCIe GbE Family Controller", &localIP))
    {
        std::cerr << "Failed to get local IP address!\n";
        return 1;
    }

    //std::cout << "Mask: " << localIP.IpMask.String << '\n';
    //std::cout << "Broadcast: " << Helper::getBroadcastAddress<std::string>(localIP) << '\n';
    //std::cout << "Minimum: " << Helper::longToIp(Helper::getMinAddress(localIP)) << '\n';

    //in_addr addr;
    //addr.s_addr = Helper::ipToLong("10.100.102.1");
    //std::cout << addr.s_addr << '\n';
    //std::cout << Sender::SendPing(addr);

    Sender::mapLocalNetwork(localIP);

    //in_addr target;
    //target.S_un.S_un_b.s_b1 = 10;
    //target.S_un.S_un_b.s_b2 = 100;
    //target.S_un.S_un_b.s_b3 = 102;
    //target.S_un.S_un_b.s_b4 = 1;

    //std::cout << "Sending ping: " << Sender::SendPing(target) << '\n';

    return 0;
}
