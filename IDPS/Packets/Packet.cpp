#include "../IDPSExceptions.hpp"
#include "Packet.h"
#include <iostream>


Packet::Packet(std::span<const uint8_t> rawData, bool hasTimestamp) :
    timestamp(hasTimestamp ? *reinterpret_cast<const Timestamp*>(rawData.data()) : 0) // Set timestamp based on flag
{
    if (hasTimestamp)
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
    else // is Loopback header
    {
        this->networkProtocol = IPV4; // Assume IPv4 when loopback
        offset += sizeof(LoopbackHeader);
        std::cout << "\n\033[41mLoopback:\033[0m\n" << tempHeader << '\n';
    }

    // Parse NETWORK layer
    switch (this->networkProtocol)
    {
    case IPV4:
    {
        std::cout << "\033[42mIP";
        auto ipv4Header = headerCtor.operator()<IPv4Header>();
        this->networkHeader = ipv4Header;
        this->transportProtocol = ipv4Header->protocol;
        break;
    }

    case ARP:
        std::cout << "\033[42mARP";
        this->networkHeader = headerCtor.operator()<ArpHeader>();
        this->transportProtocol = NONE;
        return; // No transport layer!

    default: // Probably IPv6
        throw MinorException("Unsupported network protocol");
    }

    // Parse TRANSPORT layer
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

    // Parse APPLICATION layer
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
    delete linkHeader;
    delete networkHeader;
    delete transportHeader;
    delete applicationData;
}
