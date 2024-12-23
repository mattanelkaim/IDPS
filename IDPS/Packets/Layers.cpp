//#include "../Helper.h"
#include "Layers.h"
#include <iomanip> // std::setw, std::setfill
#include <stdexcept> // std::runtime_error


EthernetHeader::EthernetHeader(const std::vector<uint8_t>& rawData)
{
    if (rawData.size() < sizeof(EthernetHeader)) [[unlikely]]
        throw std::runtime_error("Invalid Ethernet header size");
    
    // Copy raw data into the struct
    *this = *reinterpret_cast<const EthernetHeader*>(rawData.data());

    // Convert to big endian if needed
    this->etherType = toBigEndian(this->etherType);
}

std::ostream& operator<<(std::ostream& os, const EthernetHeader& obj)
{
    os << std::hex << std::setfill('0') << "Destination MAC: ";
    for (size_t i = 0; i < 5; ++i)
        os << std::setw(2) << static_cast<int>(obj.dstMAC[i]) << ":";
    os << std::setw(2) << static_cast<int>(obj.dstMAC[5]); // Print last without colon

    os << "\nSource MAC:      ";
    for (size_t i = 0; i < 5; ++i)
        os << std::setw(2) << static_cast<int>(obj.srcMAC[i]) << ":";
    os << std::setw(2) << static_cast<int>(obj.srcMAC[5]); // Print last without colon

    os << "\nEthernet type:   " << std::dec << obj.etherType << '\n';
    return os;
}


IPv4Header::IPv4Header(const std::vector<uint8_t>& rawData)
{
    if (rawData.size() < sizeof(IPv4Header)) [[unlikely]]
        throw std::runtime_error("Invalid IPv4 header size");
    
    // Copy raw data into the struct
    *this = *reinterpret_cast<const IPv4Header*>(rawData.data());

    // Convert to big endian if needed
    this->totalLength = toBigEndian(this->totalLength);
    this->identification = toBigEndian(this->identification);
    this->flagsAndFragmentOffset = toBigEndian(this->flagsAndFragmentOffset);
    this->protocol = toBigEndian(this->protocol);
    this->checksum = toBigEndian(this->checksum);
    this->srcIP = toBigEndian(this->srcIP);
    this->dstIP = toBigEndian(this->dstIP);
}

std::ostream& operator<<(std::ostream& os, const IPv4Header& obj)
{
    os << "Version: " << static_cast<int>(obj.versionAndHeaderLength >> 4) << '\n';
    os << "Header length: " << static_cast<int>(obj.versionAndHeaderLength & 0x0F) << '\n';
    os << "Type of service: " << static_cast<int>(obj.typeOfService) << '\n';
    os << "Total length: " << obj.totalLength << '\n';
    os << "Identification: " << obj.identification << '\n';
    os << "Flags: " << static_cast<int>(obj.flagsAndFragmentOffset >> 13) << '\n';
    os << "Fragment offset: " << (obj.flagsAndFragmentOffset & 0x1FFF) << '\n';
    os << "Time to live: " << static_cast<int>(obj.timeToLive) << '\n';
    os << "Protocol: " << obj.protocol << '\n';
    os << "Checksum: " << obj.checksum << '\n';
    //os << "Source IP: " << Helper::ipToString(obj.srcIP) << '\n';
    //os << "Destination IP: " << Helper::ipToString(obj.dstIP) << '\n';
    return os;
}