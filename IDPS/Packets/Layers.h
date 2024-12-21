#pragma once

#include <cstdint>
#include <vector>

enum ProtocolCode : uint16_t
{
    IPV4 = 0x0800,
    IPV6 = 0x86DD,
    TCP = 0x06,
    UDP = 0x11,
    ARP = 0x0806,
};

// TODO: Implement constructors

struct EthernetHeader
{
    uint8_t destinationMAC[6];
    uint8_t sourceMAC[6];
    ProtocolCode etherType; // Indicates the protocol (IPv4 | IPv6 | no ip i.e. ARP)

    // Constructor to initialize from raw data
    EthernetHeader(const std::vector<uint8_t> rawData);
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
    uint16_t headerChecksum;
    uint32_t sourceAddress;
    uint32_t destinationAddress;

    IPv4Header(const std::vector<uint8_t> rawData);
};

struct TransportHeader
{
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint16_t checksum;

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

    TCPHeader(const std::vector<uint8_t> rawData);
};

struct UDPHeader : TransportHeader
{
    uint16_t length;

    UDPHeader(const std::vector<uint8_t> rawData);
};
