#include "Packets/Layers.h"
#include "Packets/Packet.h"
#include "Sender.hpp"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

std::vector<uint8_t> readFile(const std::string& filename)
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

void printHexBuffer(const std::vector<uint8_t>& buffer, const size_t first = 0, const size_t second = 0, const size_t third = 0)
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
    const std::vector<uint8_t> rawData = readFile("dns packet.bin");
 
    printHexBuffer(rawData, sizeof(EthernetHeader), sizeof(IPv4Header), sizeof(UDPHeader));

    //const std::vector<uint8_t> ethernet(rawData.cbegin(), rawData.cbegin() + sizeof(EthernetHeader));
    //EthernetHeader ethHeader(ethernet);
    //std::cout << "\n\033[41mEthernet:\033[0m\n" << ethHeader << '\n';

    //const std::vector<uint8_t> ipv4(rawData.cbegin() + sizeof(EthernetHeader), rawData.cbegin() + sizeof(EthernetHeader) + sizeof(IPv4Header));
    //IPv4Header ipHeader(ipv4);
    //std::cout << "\033[42mIP:\033[0m\n" << ipHeader << '\n';

    //const std::vector<uint8_t> tcp(rawData.cbegin() + sizeof(EthernetHeader) + sizeof(IPv4Header), rawData.cbegin() + sizeof(EthernetHeader) + sizeof(IPv4Header) + sizeof(TCPHeader));
    //TCPHeader tcpHeader(tcp);
    //std::cout << "\033[43mTCP:\033[0m\n" << tcpHeader << '\n';

    //const std::string data(rawData.cbegin() + sizeof(EthernetHeader) + sizeof(IPv4Header) + sizeof(TCPHeader), rawData.cend());
    //std::cout << "\033[7mData:\033[0m\n" << data << '\n';

    //Packet packet(rawData);

#include <winsock2.h>
    in_addr broadcast;
    Sender::GetBroadcastAddress("Intel(R) Wi-Fi 6 AX201 160MHz", broadcast);
    
    /*To print a ULONG ip addr*/
    char ip[16] = {0};
    inet_ntop(AF_INET, &broadcast, ip, sizeof(ip));
    printf("\nBroadcast is: %s\n", ip);

    return 0;
}
