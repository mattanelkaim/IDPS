#include "Packets/Layers.h"
#include "Packets/Packet.h"
#include "Sender.h"
#include "PacketExtractor.h"
#include "WSAInitializer.h"
#include "Sender.h"
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
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
    WSAInitializer wsaInit;

    std::vector<uint8_t> buffer = readFile("Example Sniffs/LoopbackDNS.bin");
    Packet packet(buffer, false);

    const std::string_view question = static_cast<DNSMessage*>(packet.applicationData)->questions[0];
    std::cout << question << '\n';
    std::cout << Helper::ipToStr(Sender::DoHQuery(question.data()));

    //SOCKET sendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    //constexpr sockaddr_in clientAddr = Helper::getLocalhostDnsAddr();
    //DNSHeader header{};
    //char* response = reinterpret_cast<char*>(&header);

    //int sendResult = sendto(sendSocket,
    //                        response,
    //                        12,//sizeof(DNSHeader),
    //                        0,
    //                        reinterpret_cast<const sockaddr*>(&clientAddr),
    //                        sizeof(clientAddr));
}
