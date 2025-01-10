#include "Layers.h"
#include <ostream>
#include <stdexcept> // std::runtime_error


EthernetHeader::EthernetHeader(const std::span<const uint8_t> rawData)
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
    os << "\033[4mDestination MAC\033[0m: " << obj.dstMAC.macToString();
    os << "\n\033[4mSource MAC\033[0m:      " << obj.srcMAC.macToString();

    os << "\n\033[4mEthernet type\033[0m:   " << obj.etherType << '\n';
    return os;
}


IPv4Header::IPv4Header(const std::span<const uint8_t> rawData)
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
    os << "\033[4mVersion\033[0m: " << static_cast<int>(obj.versionAndHeaderLength >> 4) << '\n'; // High nibble
    os << "\033[4mHeader length\033[0m: " << static_cast<int>(obj.versionAndHeaderLength & 0x0F) << '\n'; // Low nibble
    os << "\033[4mType of service\033[0m: " << static_cast<int>(obj.typeOfService) << '\n';
    os << "\033[4mTotal length\033[0m: " << obj.totalLength << '\n';
    os << "\033[4mIdentification\033[0m: " << obj.identification << '\n';
    os << "\033[4mFlags\033[0m: " << static_cast<int>(obj.flagsAndFragmentOffset >> 13) << '\n'; // High 3 bits
    os << "\033[4mFragment offset\033[0m: " << (obj.flagsAndFragmentOffset & 0x1FFF) << '\n'; // Low 13 bits
    os << "\033[4mTime to live\033[0m: " << static_cast<int>(obj.timeToLive) << '\n';
    os << "\033[4mProtocol\033[0m: " << static_cast<int>(obj.protocol) << '\n';
    os << "\033[4mChecksum\033[0m: " << obj.checksum << '\n';
    os << "\033[4mSource IP\033[0m: " << Helper::longToIp(obj.srcIP) << '\n';
    os << "\033[4mDestination IP\033[0m: " << Helper::longToIp(obj.dstIP) << '\n';
    return os;
}


TCPHeader::TCPHeader(const std::span<const uint8_t> rawData)
{
    if (rawData.size() < sizeof(TCPHeader)) [[unlikely]]
        throw std::runtime_error("Invalid TCP header size");

    // Copy raw data into the struct
    *this = *reinterpret_cast<const TCPHeader*>(rawData.data());

    // Convert to big endian if needed
    this->srcPort = Helper::toBigEndian(this->srcPort);
    this->dstPort = Helper::toBigEndian(this->dstPort);
    this->checksum = Helper::toBigEndian(this->checksum);
    this->seqNumber = Helper::toBigEndian(this->seqNumber);
    this->ackNumber = Helper::toBigEndian(this->ackNumber);
    this->windowSize = Helper::toBigEndian(this->windowSize);
    this->urgentPointer = Helper::toBigEndian(this->urgentPointer);

    return;
}

std::ostream& operator<<(std::ostream& os, const TCPHeader& obj)
{
    os << "\033[4mSource port\033[0m: " << obj.srcPort << '\n';
    os << "\033[4mDestination port\033[0m: " << obj.dstPort << '\n';
    os << "\033[4mSequence number\033[0m: " << obj.seqNumber << '\n';
    os << "\033[4mAcknowledgment Number\033[0m: " << obj.ackNumber << '\n';
    os << "\033[4mData Offset\033[0m: " << static_cast<int>(obj.dataOffsetAndReserved >> 4) << '\n'; // High nibble
    os << "\033[4mReserved\033[0m: " << static_cast<int>((obj.dataOffsetAndReserved & 0b00001110) >> 1) << '\n'; // 3 high bits in lower nibble

    // Flags
    os << "\033[4mFlags\033[0m: ";
    if (obj.flags & 0x01) os << "FIN ";
    if (obj.flags & 0x02) os << "SYN ";
    if (obj.flags & 0x04) os << "RST ";
    if (obj.flags & 0x08) os << "PSH ";
    if (obj.flags & 0x10) os << "ACK ";
    if (obj.flags & 0x20) os << "URG ";
    if (obj.dataOffsetAndReserved & 0x01) os << "Reserved ";  // The 9th flag bit

    os << "\n\033[4mWindow size\033[0m: " << obj.windowSize << '\n';
    os << "\033[4mChecksum\033[0m: " << obj.checksum << '\n';
    os << "\033[4mUrgent pointer\033[0m: " << obj.urgentPointer << '\n';

    return os;
}


UDPHeader::UDPHeader(const std::span<const uint8_t> rawData)
{
    if (rawData.size() < sizeof(UDPHeader)) [[unlikely]]
        throw std::runtime_error("Invalid UDP header size");

    // Copy raw data into the struct
    *this = *reinterpret_cast<const UDPHeader*>(rawData.data());

    // Convert to big endian if needed
    this->srcPort = Helper::toBigEndian(this->srcPort);
    this->dstPort = Helper::toBigEndian(this->dstPort);
    this->length = Helper::toBigEndian(this->length);
    this->checksum = Helper::toBigEndian(this->checksum);
}

std::ostream& operator<<(std::ostream& os, const UDPHeader& obj)
{
    os << "\033[4mSource port\033[0m: " << obj.srcPort << '\n';
    os << "\033[4mDestination port\033[0m: " << obj.dstPort << '\n';
    os << "\033[4mLength\033[0m: " << obj.length << '\n';
    os << "\033[4mChecksum\033[0m: " << obj.checksum << '\n';
    return os;
}
