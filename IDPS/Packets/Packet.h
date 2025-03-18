#pragma once

#include "../Helper.h"
#include "Layers.h"
#include <span>

using Timestamp = uint64_t; // Amount of 100-nanosecond intervals since last system startup

class Packet
{
public:
    Packet(std::span<const uint8_t> rawData, bool hasTimestamp=true);
    ~Packet() noexcept;

    ProtocolCode_16 networkProtocol;
    ProtocolCode_8 transportProtocol;
    Timestamp timestamp;

    // Parsed protocol layers
    LinkHeader* linkHeader = nullptr; // If nullptr then Null protocol (loopback)
    NetworkHeader* networkHeader = nullptr;
    TransportHeader* transportHeader = nullptr;
    ApplicationData* applicationData = nullptr;

    // Helper functions
    bool isArpReplyPacket() const noexcept;
    bool isIPv4Packet() const noexcept;
    bool isTcpPacket() const noexcept;
    bool isUdpPacket() const noexcept;
    bool isDnsPacket() const noexcept;

private:
    static constexpr size_t MIN_PACKET_SIZE = sizeof(Timestamp) + sizeof(LoopbackHeader);
    void parseLink(std::span<const uint8_t> rawData, size_t& offset, auto headerCtor);
    bool parseNetwork(auto headerCtor);
    void parseTransport(auto headerCtor);
    void parseApplication(std::span<const uint8_t> rawData, const size_t& offset, auto headerCtor);
};
