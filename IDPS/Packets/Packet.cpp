#include "../IDPSExceptions.hpp"
#include "Packet.h"


Packet::Packet(std::span<const uint8_t> rawData, bool hasTimestamp)
{
    if (rawData.size() < MIN_PACKET_SIZE)
        throw MinorException("Invalid packet received");

    if (hasTimestamp) [[likely]]
    {
        this->timestamp = *reinterpret_cast<const Timestamp*>(rawData.data());
        DBG_COUT("\033[48;5;57mTimestamp:\033[0m " << timestamp << '\n');
    }

    // An initial offset depending on timestamp
    size_t offset = hasTimestamp ? sizeof(timestamp) : 0;

    // Parse the packet layers
    this->parseLink(rawData, offset);
    if (!this->parseNetwork(rawData, offset)) [[unlikely]] return; // May return early if ARP packet
    this->parseTransport(rawData, offset);
    this->parseApplication(rawData, offset);
}

void Packet::parseLink(std::span<const uint8_t> rawData, size_t& offset) noexcept(!DEBUG)
{
    // Try to parse link layer as loopback
    const LoopbackHeader tempHeader(rawData.subspan(offset, sizeof(LoopbackHeader)));

    // Try to parse the link layer
    if (tempHeader.loopbackType != NULL_IPV4) [[likely]]
    {
        DBG_COUT("\n\033[41mEthernet");
        auto ethernetHeader = headerCtor<EthernetHeader>(rawData, offset);
        this->linkHeader = ethernetHeader;
        this->networkProtocol = ethernetHeader->etherType;
    }
    else // Loopback header
    {
        this->networkProtocol = IPV4; // Assume IPv4 when loopback
        offset += sizeof(LoopbackHeader);
        DBG_COUT("\n\033[41mLoopback:\033[0m\n" << tempHeader << '\n');
    }
}

bool Packet::parseNetwork(std::span<const uint8_t> rawData, size_t& offset)
{
    switch (this->networkProtocol)
    {
    case IPV4:
    {
        DBG_COUT("\033[42mIPv4");
        auto ipv4Header = headerCtor<IPv4Header>(rawData, offset);
        this->networkHeader = ipv4Header;
        this->transportProtocol = ipv4Header->protocol;
        return true;
    }

    case ARP:
        DBG_COUT("\033[42mARP");
        this->networkHeader = headerCtor<ArpHeader>(rawData, offset);
        this->transportProtocol = NONE;
        return false; // Done parsing - no transport layer!

    default: // Probably IPv6
        throw MinorException("Unsupported network protocol");
    }
}

void Packet::parseTransport(std::span<const uint8_t> rawData, size_t& offset)
{
    switch (this->transportProtocol)
    {
    case TCP:
        DBG_COUT("\033[43mTCP");
        this->transportHeader = headerCtor<TCPHeader>(rawData, offset);
        break;

    case UDP:
        DBG_COUT("\033[43mUDP");
        this->transportHeader = headerCtor<UDPHeader>(rawData, offset);
        break;

    default:
        throw MinorException("Unsupported transport protocol");
    }
}

void Packet::parseApplication(std::span<const uint8_t> rawData, size_t offset) noexcept(!DEBUG)
{
    if (this->isDnsPacket())
    {
        this->applicationData = new DNSMessage(rawData.subspan(offset));
        DBG_COUT("\033[44mDNS (header)\033[0m:\n" << static_cast<DNSMessage*>(applicationData)->header << '\n');
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
