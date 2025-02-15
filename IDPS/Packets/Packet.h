#pragma once

#include "../Helper.h"
#include "Layers.h"
#include <span>

using Timestamp = uint64_t; // Amount of 100-nanosecond intervals since last system startup

class Packet
{
public:
    explicit Packet(std::span<const uint8_t> rawData);
    ~Packet();

    ProtocolCode_8 transportProtocol;
    Timestamp timestamp;

    // Parsed protocol layers
    EthernetHeader* ethernetHeader = nullptr;
    NetworkHeader* networkHeader = nullptr;
    TransportHeader* transportHeader = nullptr;
    ApplicationData* applicationData = nullptr;

    // Helper functions
    bool isArpReplyPacket() const noexcept;
    bool isIPv4Packet() const noexcept;
    bool isTcpPacket() const noexcept;
    bool isUdpPacket() const noexcept;
    bool isDnsPacket() const noexcept;
};
