#pragma once

#include "../Helper.h"
#include "Layers.h"
#include <span>
#include <string>

class Packet
{
public:
    explicit Packet(std::span<const uint8_t> rawData);
    ~Packet();

    std::string srcIP;
    std::string dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    ProtocolCode_8 transportProtocol;

    // Parsed protocol layers
    EthernetHeader* ethernetHeader = nullptr;
    NetworkHeader* networkHeader = nullptr;
    TransportHeader* transportHeader = nullptr;
    ApplicationData* applicationData = nullptr;
};
