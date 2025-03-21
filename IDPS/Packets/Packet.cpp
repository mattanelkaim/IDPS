#include "../IDPSExceptions.hpp"
#include "Packet.h"


Packet::Packet(std::span<const uint8_t> rawData, bool hasTimestamp)
{
    if (rawData.size() < MIN_PACKET_SIZE)
        throw MinorException("Invalid packet received");

    if (hasTimestamp) [[likely]]
    {
        this->timestamp = *reinterpret_cast<const Timestamp*>(rawData.data());
        Helper::dbgPrintln("\033[48;5;57mTimestamp\033[0m: ", timestamp);
    }

    // An initial offset depending on timestamp
    size_t offset = hasTimestamp ? sizeof(timestamp) : 0;

    // Parse the packet layers
    if (!this->parseLink(rawData, offset)) [[unlikely]]
        throw MinorException("Detected useless IEEE 802.3");

    // May return early if ARP packet
    if (!this->parseNetwork(rawData, offset)) [[unlikely]] return;

    this->parseTransport(rawData, offset);
    this->parseApplication(rawData, offset);
}

bool Packet::parseLink(std::span<const uint8_t> rawData, size_t& offset)
{
    // First assume Loopback
    const LoopbackHeader tempHeader(rawData.subspan(offset, sizeof(LoopbackHeader)));

    // Check if really Loopback
    if (tempHeader.loopbackType == NULL_IPV4) [[unlikely]]
    {
        this->networkProtocol = IPV4; // Assume IPv4 when loopback
        offset += sizeof(LoopbackHeader);
        Helper::dbgPrintln("\n\033[41mLoopback\033[0m:\n", tempHeader);
        return true;
    }

    /* Else determine whether Ethernet II OR Ethernet 802.3
       Based on EtherType. If <= 1500 then it's 802.3, else it's II.
       See: https://wikipedia.org/wiki/EtherType#Overview */

    // Both links headers have the same size!
    if (rawData.size() - offset < sizeof(EthernetIIHeader))
        throw MinorException("Unsupported link protocol");

    // Assume Ethernet II and check EtherType
    Helper::dbgPrint("\n\033[41mEthernet");
    auto* ethernetHeader = headerCtor<EthernetIIHeader>(rawData, offset);
    if (ethernetHeader->etherType <= EthernetIIHeader::ETHERNET_PAYLOAD_MAX)
    {
        // SHIT! Detected IEEE 802.3, dropping useless packet
        return false;
    }

    this->linkHeader = ethernetHeader;
    this->networkProtocol = ethernetHeader->etherType;
    
    return true; // Parsed normally
}

bool Packet::parseNetwork(std::span<const uint8_t> rawData, size_t& offset)
{
    switch (this->networkProtocol)
    {
    case IPV4:
    {
        Helper::dbgPrint("\033[42mIPv4");
        auto* ipv4Header = headerCtor<IPv4Header>(rawData, offset);
        this->networkHeader = ipv4Header;
        this->transportProtocol = ipv4Header->protocol;
        return true;
    }

    case ARP:
        Helper::dbgPrint("\033[42mARP");
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
        Helper::dbgPrint("\033[43mTCP");
        this->transportHeader = headerCtor<TCPHeader>(rawData, offset);
        break;

    case UDP:
        Helper::dbgPrint("\033[43mUDP");
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
        Helper::dbgPrintln("\033[44mDNS (header)\033[0m:\n", static_cast<DNSMessage*>(applicationData)->header);
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
        delete static_cast<EthernetIIHeader*>(linkHeader);
}
