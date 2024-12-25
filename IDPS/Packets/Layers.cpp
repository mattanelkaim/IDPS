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
    this->etherType = Helper::toBigEndian(this->etherType);
}

std::ostream& operator<<(std::ostream& os, const EthernetHeader& obj)
{
    os << std::hex << std::setfill('0') << "\033[4mDestination MAC\033[0m: ";
    for (size_t i = 0; i < 5; ++i)
        os << std::setw(2) << static_cast<int>(obj.dstMAC[i]) << ":";
    os << std::setw(2) << static_cast<int>(obj.dstMAC[5]); // Print last without colon

    os << "\n\033[4mSource MAC\033[0m:      ";
    for (size_t i = 0; i < 5; ++i)
        os << std::setw(2) << static_cast<int>(obj.srcMAC[i]) << ":";
    os << std::setw(2) << static_cast<int>(obj.srcMAC[5]); // Print last without colon

    os << "\n\033[4mEthernet type\033[0m:   " << std::dec << obj.etherType << '\n';
    return os;
}


IPv4Header::IPv4Header(const std::vector<uint8_t>& rawData)
{
    if (rawData.size() < sizeof(IPv4Header)) [[unlikely]]
        throw std::runtime_error("Invalid IPv4 header size");
    
    // Copy raw data into the struct
    *this = *reinterpret_cast<const IPv4Header*>(rawData.data());

    // Convert to big endian if needed
    this->totalLength = Helper::toBigEndian(this->totalLength);
    this->identification = Helper::toBigEndian(this->identification);
    this->flagsAndFragmentOffset = Helper::toBigEndian(this->flagsAndFragmentOffset);
    this->checksum = Helper::toBigEndian(this->checksum);
    this->srcIP = Helper::toBigEndian(this->srcIP);
    this->dstIP = Helper::toBigEndian(this->dstIP);
}

std::ostream& operator<<(std::ostream& os, const IPv4Header& obj)
{
    os << "\033[4mVersion\033[0m: " << static_cast<int>(obj.versionAndHeaderLength >> 4) << '\n';
    os << "\033[4mHeader length\033[0m: " << static_cast<int>(obj.versionAndHeaderLength & 0x0F) << '\n';
    os << "\033[4mType of service\033[0m: " << static_cast<int>(obj.typeOfService) << '\n';
    os << "\033[4mTotal length\033[0m: " << obj.totalLength << '\n';
    os << "\033[4mIdentification\033[0m: " << obj.identification << '\n';
    os << "\033[4mFlags\033[0m: " << static_cast<int>(obj.flagsAndFragmentOffset >> 13) << '\n';
    os << "\033[4mFragment offset\033[0m: " << (obj.flagsAndFragmentOffset & 0x1FFF) << '\n';
    os << "\033[4mTime to live\033[0m: " << static_cast<int>(obj.timeToLive) << '\n';
    os << "\033[4mProtocol\033[0m: " << static_cast<int>(obj.protocol) << '\n';
    os << "\033[4mChecksum\033[0m: " << obj.checksum << '\n';
    os << "\033[4mSource IP\033[0m: " << Helper::ipToString(obj.srcIP) << '\n';
    os << "\033[4mDestination IP\033[0m: " << Helper::ipToString(obj.dstIP) << '\n';
    return os;
}
