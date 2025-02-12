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
    constexpr bool isArpReplyPacket() const noexcept;
    constexpr bool isIPv4Packet() const noexcept;
    constexpr bool isTcpPacket() const noexcept;
    constexpr bool isUdpPacket() const noexcept;
    constexpr bool isDnsPacket() const noexcept;
};
