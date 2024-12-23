#include "Packets/Layers.h"
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

void printHexBuffer(const std::vector<uint8_t>& buffer, const size_t highlight = 0)
{
    // Read byte by byte and print in a nice hex format
    std::cout << std::hex << std::setfill('0') << "\033[31m"; // Formatting + red color
    for (size_t i = 0; i < highlight; ++i)
        std::cout << std::setw(2) << static_cast<int>(buffer[i]) << " ";

    // Print second half (not highlighted)
    std::cout << "\033[0m"; // Reset color
    for (size_t i = highlight; i < buffer.size(); ++i)
        std::cout << std::setw(2) << static_cast<int>(buffer[i]) << " ";

    std::cout << std::dec << '\n';
}

int main()
{
    const std::vector<uint8_t> rawData = readFile("http packet.bin");
 
    printHexBuffer(rawData, 14);

    const std::vector<uint8_t> ethernet(rawData.cbegin(), rawData.cbegin() + sizeof(EthernetHeader));
    EthernetHeader ethHeader(ethernet);
    std::cout << ethHeader << '\n';

    const std::vector<uint8_t> ipv4(rawData.cbegin() + sizeof(EthernetHeader), rawData.cbegin() + sizeof(EthernetHeader) + sizeof(IPv4Header));
    IPv4Header ipHeader(ipv4);
    std::cout << ipHeader << '\n';

    return 0;
}
