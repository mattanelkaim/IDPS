#include "Packet.h"
#include "../IDPSExceptions.hpp"
#include <iostream>


Packet::Packet(const std::span<const uint8_t> rawData, bool hasTimestamp) :
    timestamp(hasTimestamp ? *reinterpret_cast<const uint64_t*>(rawData.data()) : 0) // Set timestamp based on flag
{
    if (hasTimestamp)
        std::cout << "\033[48;5;57mTimestamp:\033[0m " << timestamp << '\n';

    // An initial offset depending on timestamp
    size_t offset = hasTimestamp ? sizeof(timestamp) : 0;

    // Try to parse link layer as loopback
    const LoopbackHeader tempHeader(rawData.subspan(offset, sizeof(LoopbackHeader)));

    // Try to parse the link layer
    if (tempHeader.loopbackType != NULL_IPV4) [[likely]]
    {
        this->linkHeader = new EthernetHeader(rawData.subspan(offset, sizeof(EthernetHeader)));
        this->networkProtocol = static_cast<EthernetHeader*>(linkHeader)->etherType;
        std::cout << "\n\033[41mEthernet:\033[0m\n" << *static_cast<EthernetHeader*>(linkHeader) << '\n';
        offset += sizeof(EthernetHeader);
    }
    else // is Loopback header
    {
        this->networkProtocol = IPV4;
        std::cout << "\n\033[41mLoopback:\033[0m\n" << tempHeader << '\n';
        offset += sizeof(LoopbackHeader);
    }

    // Parse NETWORK layer
    if (this->networkProtocol == IPV4)
    {
    case IPV4:
        this->networkHeader = new IPv4Header(rawData.subspan(offset, sizeof(IPv4Header)));
        offset += sizeof(IPv4Header);
        this->transportProtocol = static_cast<IPv4Header*>(networkHeader)->protocol;
        std::cout << "\033[42mIP:\033[0m\n" << *static_cast<IPv4Header*>(networkHeader) << '\n';
        break;

    case ARP:
        this->networkHeader = new ArpHeader(rawData.subspan(offset, sizeof(ArpHeader)));
        this->transportProtocol = NONE;
        std::cout << "\033[42mIP:\033[0m\n" << *static_cast<ArpHeader*>(networkHeader) << '\n';
        return; // No transport layer!

    default: // Probably IPv6
        throw MinorException("Unsupported network protocol");
    }

    // Parse TRANSPORT layer
    switch (this->transportProtocol)
    {
    case TCP:
        this->transportHeader = new TCPHeader(rawData.subspan(offset, sizeof(TCPHeader)));
        offset += sizeof(TCPHeader);
        std::cout << "\033[43mTCP:\033[0m\n" << *static_cast<TCPHeader*>(transportHeader) << '\n';
        break;

    case UDP:
        this->transportHeader = new UDPHeader(rawData.subspan(offset, sizeof(UDPHeader)));
        offset += sizeof(UDPHeader);
        std::cout << "\033[43mUDP:\033[0m\n" << *static_cast<UDPHeader*>(transportHeader) << '\n';
        break;

    default:
        throw MinorException("Unsupported transport protocol");
    }

    // Parse APPLICATION layer
    if (this->isDnsPacket())
    {
        this->applicationData = new DNSMessage(rawData.subspan(offset));
        std::cout << "\033[44mDNS (header):\033[0m\n" << static_cast<DNSMessage*>(applicationData)->header << '\n';
    }
}

bool Packet::isArpReplyPacket() const noexcept
{
    return this->ethernetHeader->etherType == ARP && reinterpret_cast<ArpHeader*>(this->networkHeader)->opcode == REPLY;
}

bool Packet::isIPv4Packet() const noexcept
{
    return this->ethernetHeader->etherType == IPV4;
}

bool Packet::isTcpPacket() const noexcept
{
    return this->transportProtocol == TCP;
}

bool Packet::isDnsPacket() const noexcept
{
    return this->transportHeader->srcPort == DNSHeader::DEFAULT_PORT ||
           this->transportHeader->dstPort == DNSHeader::DEFAULT_PORT;
}

bool Packet::isUdpPacket() const noexcept
{
    return this->transportProtocol == UDP;
}

Packet::~Packet()
{
    delete linkHeader;
    delete networkHeader;
    delete transportHeader;
    delete applicationData;
}
