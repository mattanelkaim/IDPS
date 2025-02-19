#pragma once

#include "../Helper.h"
#include "Layers.h"
#include <span>

class Packet
{
public:
    Packet(std::span<const uint8_t> rawData, bool hasTimestamp=true);
    ~Packet();

    ProtocolCode_16 networkProtocol;
    ProtocolCode_8 transportProtocol;
    uint64_t timestamp;

    // Parsed protocol layers
    LinkHeader* linkHeader = nullptr; // If nullptr then Null protocol (loopback)
    NetworkHeader* networkHeader = nullptr;
    TransportHeader* transportHeader = nullptr;
    ApplicationData* applicationData = nullptr;
};
