#pragma once

#include "../Helper.h"
#include "Layers.h"
#include <span>

class Packet
{
public:
    Packet(std::span<const uint8_t> rawData, bool hasTimestamp=true);
    ~Packet();

    ProtocolCode_8 transportProtocol;
    uint64_t timestamp;

    // Parsed protocol layers
    EthernetHeader* ethernetHeader = nullptr;
    NetworkHeader* networkHeader = nullptr;
    TransportHeader* transportHeader = nullptr;
    ApplicationData* applicationData = nullptr;
};
