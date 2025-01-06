#pragma once

#include "../Helper.h"
#include <cstdint>
#include <iosfwd> // std::ostream
#include <span>

#pragma pack(push, 1) // All structs must be packed because of alignment

struct EthernetHeader
{
    mac dstMAC;
    mac srcMAC;
    ProtocolCode_16 etherType; // Indicates the protocol (IPv4 | IPv6 | no ip i.e. ARP)

public:
    explicit EthernetHeader(std::span<const uint8_t> rawData);
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
    ProtocolCode_8 protocol; // Indicates upper-layer (TCP | UDP)
    uint16_t checksum;
    uint32_t srcIP;
    uint32_t dstIP;

public:
    explicit IPv4Header(std::span<const uint8_t> rawData);
    friend std::ostream& operator<<(std::ostream& os, const IPv4Header& obj);
};

struct TransportHeader
{
    //TransportHeader() = delete;
};

struct TCPHeader : public TransportHeader
{
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNumber;
    uint32_t ackNumber;
    uint8_t dataOffsetAndReserved;
    uint8_t flags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;

public:
    explicit TCPHeader(std::span<const uint8_t> rawData);
    friend std::ostream& operator<<(std::ostream& os, const TCPHeader& obj);
};

struct UDPHeader : public TransportHeader
{
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;

public:
    explicit UDPHeader(std::span<const uint8_t> rawData);
    friend std::ostream& operator<<(std::ostream& os, const UDPHeader& obj);
};

#pragma pack(pop)
