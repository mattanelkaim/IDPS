#pragma once

#include "../Helper.h"
#include "Layers.h"
#include <span>

class Packet
{
public:
    explicit Packet(std::span<const uint8_t> rawData);
    ~Packet();

    ProtocolCode_8 transportProtocol;

    // Parsed protocol layers
    EthernetHeader* ethernetHeader = nullptr;
    NetworkHeader* networkHeader = nullptr;
    TransportHeader* transportHeader = nullptr;
    ApplicationData* applicationData = nullptr;
};
