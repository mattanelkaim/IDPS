#pragma once

#include "../Helper.h"
#include "Layers.h"
#include <span>

using Timestamp = uint64_t; // Amount of 100-nanosecond intervals since last system startup

class Packet
{
public:
    explicit Packet(std::span<const uint8_t> rawData, bool hasTimestamp=true);
    ~Packet() noexcept;

    // Parsed protocol layers
    LinkHeader* linkHeader = nullptr; // If nullptr then Null protocol (loopback)
    NetworkHeader* networkHeader = nullptr;
    TransportHeader* transportHeader = nullptr;
    ApplicationData* applicationData = nullptr;

    // Other members
    Timestamp timestamp;
    ProtocolCode_16 networkProtocol;
    ProtocolCode_8 transportProtocol;

    // Helper functions
    bool isArpReplyPacket() const noexcept;
    bool isIPv4Packet() const noexcept;
    bool isTcpPacket() const noexcept;
    bool isUdpPacket() const noexcept;
    bool isDnsPacket() const noexcept;

private:
    static constexpr size_t MIN_PACKET_SIZE = sizeof(Timestamp) + sizeof(LoopbackHeader);

    bool parseLink(std::span<const uint8_t> rawData, size_t& offset);
    bool parseNetwork(std::span<const uint8_t> rawData, size_t& offset);
    void parseTransport(std::span<const uint8_t> rawData, size_t& offset);
    void parseApplication(std::span<const uint8_t> rawData, size_t offset) noexcept(!DEBUG); // No need for reference (last layer)

    template <typename T>
    static T* headerCtor(std::span<const uint8_t> rawData, size_t& offset) noexcept(!DEBUG)
    {
        T* header = new T(rawData.subspan(offset, sizeof(T)));
        offset += sizeof(T); // By reference
        Helper::dbgPrintln("\033[0m:\n", *header); // Prints a prefix and the header
        return header;
    };
};
