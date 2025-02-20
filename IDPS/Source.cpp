#include "Distributer.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

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
    try
    {
        Distributer::getInstance().run();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what();
    }
}

/*
IP:
Version: 4
Header length: 5
Type of service: 136
Total length: 68
Identification: 46027
Flags: 2
Fragment offset: 0
Time to live: 59
Protocol: 17
Checksum: 0x18a8
Source IP: 1.1.1.1
Destination IP: 10.100.102.72

TCP:
Source port: 80
Destination port: 21119
Sequence number: 2120307519
Acknowledgment Number: 4065945401
Data Offset: 5
Reserved: 0
Flags: PSH ACK
Window size: 501
Checksum: 0xb49a
Urgent pointer: 0
*/