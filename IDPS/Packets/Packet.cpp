#include "../IDPSExceptions.hpp"
#include "Packet.h"
#include <iostream>


Packet::Packet(std::span<const uint8_t> rawData, bool hasTimestamp) :
    timestamp(hasTimestamp ? *reinterpret_cast<const Timestamp*>(rawData.data()) : 0) // Set timestamp based on flag
{
    if (hasTimestamp) [[likely]]
        std::cout << "\033[48;5;57mTimestamp:\033[0m " << timestamp << '\n';

    // An initial offset depending on timestamp
    size_t offset = hasTimestamp ? sizeof(timestamp) : 0;

    // Captures offset & rawData by ref. Then it's called using headerCtor.operator()<T>()
    auto headerCtor = [&]<typename T>() -> T* {
        T* header = new T(rawData.subspan(offset, sizeof(T)));
        offset += sizeof(T); // By reference
        std::cout << "\033[0m:\n" << *header << '\n'; // Prints a prefix and the header
        return header;
    };

    // Parse the packet layers
    this->parseLink(rawData, offset, headerCtor);
    if (!this->parseNetwork(headerCtor)) [[unlikely]] return; // May return early if ARP packet
    this->parseTransport(headerCtor);
    this->parseApplication(rawData, offset, headerCtor);
}

void Packet::parseLink(std::span<const uint8_t> rawData, size_t& offset, auto headerCtor)
{
    // Try to parse link layer as loopback
    const LoopbackHeader tempHeader(rawData.subspan(offset, sizeof(LoopbackHeader)));

    // Try to parse the link layer
    if (tempHeader.loopbackType != NULL_IPV4) [[likely]]
    {
        std::cout << "\n\033[41mEthernet";
        auto ethernetHeader = headerCtor.operator()<EthernetHeader>();
        this->linkHeader = ethernetHeader;
        this->networkProtocol = ethernetHeader->etherType;
    }
    else // Loopback header
    {
        this->networkProtocol = IPV4; // Assume IPv4 when loopback
        offset += sizeof(LoopbackHeader);
        std::cout << "\n\033[41mLoopback:\033[0m\n" << tempHeader << '\n';
    }
}

bool Packet::parseNetwork(auto headerCtor)
{
    switch (this->networkProtocol)
    {
    case IPV4:
    {
        std::cout << "\033[42mIPv4";
        auto ipv4Header = headerCtor.operator()<IPv4Header>();
        this->networkHeader = ipv4Header;
        this->transportProtocol = ipv4Header->protocol;
        return true;
    }

    case ARP:
        std::cout << "\033[42mARP";
        this->networkHeader = headerCtor.operator()<ArpHeader>();
        this->transportProtocol = NONE;
        return false; // Done parsing - no transport layer!

    default: // Probably IPv6
        throw MinorException("Unsupported network protocol");
    }
}

void Packet::parseTransport(auto headerCtor)
{
    switch (this->transportProtocol)
    {
    case TCP:
        std::cout << "\033[43mTCP";
        this->transportHeader = headerCtor.operator()<TCPHeader>();
        break;

    case UDP:
        std::cout << "\033[43mUDP";
        this->transportHeader = headerCtor.operator()<UDPHeader>();
        break;

    default:
        throw MinorException("Unsupported transport protocol");
    }
}

void Packet::parseApplication(std::span<const uint8_t> rawData, const size_t& offset, auto headerCtor)
{
    if (this->isDnsPacket())
    {
        this->applicationData = new DNSMessage(rawData.subspan(offset));
        std::cout << "\033[44mDNS (header)\033[0m:\n" << static_cast<DNSMessage*>(applicationData)->header << '\n';
    }
}


bool Packet::isArpReplyPacket() const noexcept
{
    return this->networkProtocol == ARP &&
           static_cast<ArpHeader*>(this->networkHeader)->opcode == REPLY;
}

bool Packet::isIPv4Packet() const noexcept
{
    return this->networkProtocol == IPV4;
}

bool Packet::isTcpPacket() const noexcept
{
    return this->transportProtocol == TCP;
}

bool Packet::isUdpPacket() const noexcept
{
    return this->transportProtocol == UDP;
}

bool Packet::isDnsPacket() const noexcept
{
    return this->transportHeader->srcPort == DNSHeader::DEFAULT_PORT ||
           this->transportHeader->dstPort == DNSHeader::DEFAULT_PORT;
}


Packet::~Packet() noexcept
{
    // Layer parents don't have a virtual destructor, so we must call the specific destructors
    // **IMPORTANT** deleting the layers from the uppermost (application) to the lowermost (link) layer
    
    // Delete APPLICATION layer
    if (isDnsPacket())
        delete static_cast<DNSMessage*>(applicationData);

    // Delete TRANSPORT layer
    switch (transportProtocol)
    {
    case TCP:
        delete static_cast<TCPHeader*>(transportHeader);
        break;
    case UDP:
        delete static_cast<UDPHeader*>(transportHeader);
        break;
    default:
        break;
    }

    // Delete NETWORK layer
    switch (networkProtocol)
    {
    case IPV4:
        delete static_cast<IPv4Header*>(networkHeader);
        break;
    case ARP:
        delete static_cast<ArpHeader*>(networkHeader);
        break;
    default:
        break;
    }

    // Delete LINK layer
    if (linkHeader)
        delete static_cast<EthernetHeader*>(linkHeader);
}
