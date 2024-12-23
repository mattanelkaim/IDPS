#pragma once

#include "../Helper.h"
#include <cstdint>
#include <iosfwd> // std::ostream
#include <vector>

// TODO: Implement constructors

struct EthernetHeader
{
    uint8_t dstMAC[6];
    uint8_t srcMAC[6];
    ProtocolCode etherType; // Indicates the protocol (IPv4 | IPv6 | no ip i.e. ARP)

public:
    EthernetHeader(const std::vector<uint8_t>& rawData);
    friend std::ostream& operator<<(std::ostream& os, const EthernetHeader& obj);
};

struct IPv4Header
{
    uint8_t versionAndHeaderLength;
    uint8_t typeOfService;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsAndFragmentOffset;
    uint8_t timeToLive;
    ProtocolCode protocol; // Indicates upper-layer (TCP | UDP)
    uint16_t checksum;
    uint32_t srcIP;
    uint32_t dstIP;

public:
    IPv4Header(const std::vector<uint8_t>& rawData);
    friend std::ostream& operator<<(std::ostream& os, const IPv4Header& obj);
};

struct TransportHeader
{
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint16_t checksum;

public:
    TransportHeader(const uint16_t src, const uint16_t dst, const uint16_t checksum);
};

struct TCPHeader : TransportHeader
{
    uint32_t sequenceNumber;
    uint32_t acknowledgmentNumber;
    uint8_t dataOffsetAndReserved;
    uint8_t flags;
    uint16_t windowSize;
    uint16_t urgentPointer;

public:
    TCPHeader(const std::vector<uint8_t>& rawData);
};

struct UDPHeader : TransportHeader
{
    uint16_t length;

public:
    UDPHeader(const std::vector<uint8_t>& rawData);
};
