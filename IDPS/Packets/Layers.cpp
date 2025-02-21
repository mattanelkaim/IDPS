#include "Layers.h"
#include <ostream>
#include <stdexcept> // std::runtime_error

// 4m=underline, 0m=reset ANSI
#define FIELD(name) "\033[4m" name "\033[0m: "

EthernetHeader::EthernetHeader(const std::span<const uint8_t> rawData)
{
    if (rawData.size() < sizeof(EthernetHeader)) [[unlikely]]
        throw std::runtime_error("Invalid Ethernet header size");

    // Copy raw data into the struct
    *this = *reinterpret_cast<const EthernetHeader*>(rawData.data());

    // Convert to big endian if larger than a byte
    this->etherType = Helper::toBigEndian(this->etherType);
}

std::ostream& operator<<(std::ostream& os, const EthernetHeader& obj)
{
    os << FIELD("Destination MAC") << obj.dstMAC.macToString() << '\n';
    os << FIELD("Source MAC") << obj.srcMAC.macToString() << '\n';
    os << FIELD("Ethernet type") << "0x" << std::hex << obj.etherType << std::dec << '\n';
    return os;
}


LoopbackHeader::LoopbackHeader(std::span<const uint8_t> rawData)
{
    if (rawData.size() < sizeof(LoopbackHeader)) [[unlikely]]
        throw std::runtime_error("Invalid Loopback header size");

    // Convert to big endian if larger than a byte
    this->loopbackType = static_cast<ProtocolCode_32>(*rawData.data());
}


std::ostream& operator<<(std::ostream& os, const LoopbackHeader& obj)
{
    os << FIELD("Loopback type") << "0x" << std::hex << obj.loopbackType << std::dec << '\n';
    return os;
}


IPv4Header::IPv4Header(const std::span<const uint8_t> rawData)
{
    if (rawData.size() < sizeof(IPv4Header)) [[unlikely]]
        throw std::runtime_error("Invalid IPv4 header size");

    // Copy raw data into the struct
    *this = *reinterpret_cast<const IPv4Header*>(rawData.data());

    // Convert to big endian if larger than a byte
    this->totalLength = Helper::toBigEndian(this->totalLength);
    this->identification = Helper::toBigEndian(this->identification);
    this->flagsAndFragmentOffset = Helper::toBigEndian(this->flagsAndFragmentOffset);
    this->checksum = Helper::toBigEndian(this->checksum);
    //this->srcIP.s_addr = Helper::toBigEndian(this->srcIP.s_addr);
    //this->dstIP.s_addr = Helper::toBigEndian(this->dstIP.s_addr);
}

std::ostream& operator<<(std::ostream& os, const IPv4Header& obj)
{
    os << FIELD("Version") << static_cast<int>(obj.version) << '\n'; // High nibble
    os << FIELD("Header length") << static_cast<int>(obj.headerLength) << '\n'; // Low nibble
    os << FIELD("Type of service") << static_cast<int>(obj.typeOfService) << '\n';
    os << FIELD("Total length") << obj.totalLength << '\n';
    os << FIELD("Identification") << obj.identification << '\n';
    os << FIELD("Flags") << static_cast<int>(obj.flags) << '\n'; // High 3 bits
    os << FIELD("Fragment offset") << (obj.fragmentOffset) << '\n'; // Low 13 bits
    os << FIELD("Time to live") << static_cast<int>(obj.ttl) << '\n';
    os << FIELD("Protocol") << static_cast<int>(obj.protocol) << '\n';
    os << FIELD("Checksum") << "0x" << std::hex << obj.checksum << std::dec << '\n';
    
    os << FIELD("Source IP") << Helper::ipToStr(obj.srcIP) << '\n';
    os << FIELD("Destination IP") << Helper::ipToStr(obj.dstIP) << '\n';
    
    return os;
}


ArpHeader::ArpHeader(const std::span<const uint8_t> rawData)
{
    if (rawData.size() < sizeof(ArpHeader)) [[unlikely]]
        throw std::runtime_error("Invalid ARP header size");

    // Copy raw data into the struct
    *this = *reinterpret_cast<const ArpHeader*>(rawData.data());

    // Convert to big endian if larger than a byte
    this->hardwareType = Helper::toBigEndian(this->hardwareType);
    this->protocolType = Helper::toBigEndian(this->protocolType);
    this->opcode = Helper::toBigEndian(this->opcode);
    //this->senderIP.s_addr = Helper::toBigEndian(this->senderIP.s_addr);
    //this->targetIP.s_addr = Helper::toBigEndian(this->targetIP.s_addr);
}

std::ostream& operator<<(std::ostream& os, const ArpHeader& obj)
{
    os << FIELD("Hardware type") << "0x" << std::hex << obj.hardwareType << '\n';
    os << FIELD("IP format type") << "0x" << obj.protocolType << std::dec << '\n';
    os << FIELD("Hardware length") << static_cast<int>(obj.hardwareLength) << '\n';
    os << FIELD("Protocol length") << static_cast<int>(obj.protocolLength) << '\n';
    os << FIELD("Opcode") << "0x" << std::hex << obj.opcode << std::dec << '\n';
    
    os << FIELD("Sender MAC") << obj.senderMAC.macToString() << '\n';
    os << FIELD("Sender IP") << Helper::ipToStr(obj.senderIP) << '\n';
    
    os << FIELD("Target MAC") << obj.targetMAC.macToString() << '\n';
    os << FIELD("Target IP") << Helper::ipToStr(obj.targetIP) << '\n';
    
    return os;
}


TCPHeader::TCPHeader(const std::span<const uint8_t> rawData)
{
    if (rawData.size() < sizeof(TCPHeader)) [[unlikely]]
        throw std::runtime_error("Invalid TCP header size");

    // Copy raw data into the struct
    *this = *reinterpret_cast<const TCPHeader*>(rawData.data());

    // Convert to big endian if larger than a byte
    this->srcPort = Helper::toBigEndian(this->srcPort);
    this->dstPort = Helper::toBigEndian(this->dstPort);
    this->checksum = Helper::toBigEndian(this->checksum);
    this->seqNumber = Helper::toBigEndian(this->seqNumber);
    this->ackNumber = Helper::toBigEndian(this->ackNumber);
    this->windowSize = Helper::toBigEndian(this->windowSize);
    this->urgentPointer = Helper::toBigEndian(this->urgentPointer);
}

std::ostream& operator<<(std::ostream& os, const TCPHeader& obj)
{
    os << FIELD("Source port") << obj.srcPort << '\n';
    os << FIELD("Destination port") << obj.dstPort << '\n';
    os << FIELD("Sequence number") << obj.seqNumber << '\n';
    os << FIELD("Acknowledgment Number") << obj.ackNumber << '\n';
    os << FIELD("Data Offset") << static_cast<int>(obj.dataOffset) << '\n';
    os << FIELD("Reserved") << static_cast<int>((obj.reserved & 0b1110) >> 1) << '\n'; // 3 high bits in lower nibble

    // Flags
    os << FIELD("Flags");
    if (obj.flags & 0x01) os << "FIN ";
    if (obj.flags & 0x02) os << "SYN ";
    if (obj.flags & 0x04) os << "RST ";
    if (obj.flags & 0x08) os << "PSH ";
    if (obj.flags & 0x10) os << "ACK ";
    if (obj.flags & 0x20) os << "URG ";
    if (obj.reserved & 0x01) os << "Reserved "; // The 9th flag bit

    os << '\n' << FIELD("Window size") << obj.windowSize << '\n';
    os << FIELD("Checksum") << "0x" << std::hex << obj.checksum << std::dec << '\n';
    os << FIELD("Urgent pointer") << obj.urgentPointer << '\n';

    return os;
}


UDPHeader::UDPHeader(const std::span<const uint8_t> rawData)
{
    if (rawData.size() < sizeof(UDPHeader)) [[unlikely]]
        throw std::runtime_error("Invalid UDP header size");

    // Copy raw data into the struct
    *this = *reinterpret_cast<const UDPHeader*>(rawData.data());

    // Convert to big endian if larger than a byte
    this->srcPort = Helper::toBigEndian(this->srcPort);
    this->dstPort = Helper::toBigEndian(this->dstPort);
    this->length = Helper::toBigEndian(this->length);
    this->checksum = Helper::toBigEndian(this->checksum);
}

std::ostream& operator<<(std::ostream& os, const UDPHeader& obj)
{
    os << FIELD("Source port") << obj.srcPort << '\n';
    os << FIELD("Destination port") << obj.dstPort << '\n';

    os << FIELD("Length") << obj.length << '\n';
    os << FIELD("Checksum") << "0x" << std::hex << obj.checksum << std::dec << '\n';
    
    return os;
}


DNSHeader::DNSHeader(const std::span<const uint8_t> rawData)
{
    if (rawData.size() < sizeof(DNSHeader)) [[unlikely]]
        throw std::runtime_error("Invalid DNS header size");

    // Copy raw data into the struct
    *this = *reinterpret_cast<const DNSHeader*>(rawData.data());

    // Convert to big endian if larger than a byte
    this->transactionID = Helper::toBigEndian(this->transactionID);
    this->flags = Helper::toBigEndian(this->flags);
    this->questionCount = Helper::toBigEndian(this->questionCount);
    this->answerCount = Helper::toBigEndian(this->answerCount);
    this->authorityCount = Helper::toBigEndian(this->authorityCount);
    this->additionalCount = Helper::toBigEndian(this->additionalCount);
}

std::ostream& operator<<(std::ostream& os, const DNSHeader& obj)
{
    os << FIELD("Transaction ID") << "0x" << std::hex << obj.transactionID << '\n';
    os << FIELD("Flags") << "0x" << obj.flags << std::dec << '\n';
    
    os << FIELD("Questions") << obj.questionCount << '\n';
    os << FIELD("Answers") << obj.answerCount << '\n';
    os << FIELD("Authority records") << obj.authorityCount << '\n';
    os << FIELD("Additional records") << obj.additionalCount << '\n';
    
    return os;
}


// HELPER FUNCTIONS


constexpr DNSRecord::DNSRecord(const std::span<const uint8_t> rawData) noexcept :
    name(Helper::toBigEndian(*reinterpret_cast<const uint16_t*>(rawData.data()))),
    type(Helper::toBigEndian(*reinterpret_cast<const uint16_t*>(rawData.data() + 2))),
    recordClass(Helper::toBigEndian(*reinterpret_cast<const uint16_t*>(rawData.data() + 4))),
    ttl(Helper::toBigEndian(*reinterpret_cast<const uint32_t*>(rawData.data() + 6)))
{
    // Get the data length, then extract the data
    const uint16_t dataLength = Helper::toBigEndian(*reinterpret_cast<const uint16_t*>(rawData.data() + 10));
    data.assign(rawData.data() + 12, rawData.data() + 12 + dataLength);
}


DNSMessage::DNSMessage(const std::span<const uint8_t> rawData) :
    header(rawData)
{
    size_t offset = sizeof(DNSHeader);

    // Parse Questions
    for (int i = 0; i < header.questionCount; ++i)
    {
        questions.push_back(parseDomainName(rawData, offset));
        offset += 4;  // Skip type and class
    }

    // Parse Answers, Authorities, and Additional Records
    answers = parseRecords(rawData, offset, header.answerCount);
    authorities = parseRecords(rawData, offset, header.authorityCount);
    additionalRecords = parseRecords(rawData, offset, header.additionalCount);
}

constexpr in_addr DNSMessage::getResolvedIP() const noexcept
{
    for (const DNSRecord& record : answers)
    {
        if (record.type == 1) // Type A (IPv4 address)
            return *reinterpret_cast<const in_addr*>(record.data.data()); // Data is stored and aligned as an in_addr
    }
    return {0}; // Invalid IP
}

constexpr std::string DNSMessage::parseDomainName(const std::span<const uint8_t> rawData, size_t& offset) noexcept
{
    std::string domainName;

    // Append each label to the domain name, separated by dots
    while (rawData[offset] != 0) // Loop until null terminator
    {
        const uint8_t labelLength = rawData[offset]; // A single byte indicates the label length
        domainName.append(reinterpret_cast<const char*>(rawData.data() + offset + 1), labelLength);
        domainName += ".";
        offset += labelLength + 1;
    }

    ++offset; // Skip the null terminator
    domainName.pop_back(); // Remove the trailing dot
    return domainName;
}

constexpr std::vector<DNSRecord> DNSMessage::parseRecords(std::span<const uint8_t> rawData, size_t& offset, uint16_t count) noexcept
{
    std::vector<DNSRecord> records;
    for (int i = 0; i < count; ++i)
    {
        records.emplace_back(rawData.subspan(offset));
        offset += 12 + records.back().data.size(); // Skip the header and data part
    }
    return records;
}
