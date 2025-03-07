#include "Distributer.h"
#include "IDPSExceptions.hpp"
#include "Detector.h"
#include "PacketExtractor.h"
#include "Packets/Layers.h"
#include "Packets/Packet.h"
#include "Sender.h"
#include "WSAInitializer.h"
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

static std::vector<uint8_t> readFile(std::string_view filename)
{
    // Open raw packet file
    std::ifstream file(filename.data(), std::ios::binary);
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

static void printHexBuffer(const std::vector<uint8_t>& buffer, size_t first = 0, size_t second = 0, size_t third = 0)
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
    try
    {
        WSAInitializer wsaInit;
        Distributer::getInstance().run();
    }
    catch (const FatalException& e)
    {
        std::cerr << "Fatal exception caught: " << e.what() << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cerr << "General exception caught: " << e.what() << std::endl;
    }

    /*

    std::vector<uint8_t> buffer = readFile("Example Sniffs/dns response.bin");
    Packet packet(buffer, false);*/

    //Sender::sendDNSResponse(packet);

    //std::cout << Sender::DoHQuery("catalog.gamepass.com") << '\n';
}

/*
Ethernet:
Destination MAC: DC:97:E6:F6:7E:87
Source MAC: A8:5E:45:B5:21:F4
Ethernet type: 0x800

IP:
Version: 4
Header length: 5
Type of service: 0
Total length: 66
Identification: 49950
Flags: 0
Fragment offset: 0
Time to live: 128
Protocol: 17
Checksum: 0x0
Source IP: 10.100.102.4
Destination IP: 1.1.1.1

UDP:
Source port: 56445
Destination port: 53
Length: 46
Checksum: 0x72a9

DNS (header):
Transaction ID: 0xd7a8
Flags: 0x100
Questions: 1
Answers: 0
Authority records: 0
Additional records: 0
*/