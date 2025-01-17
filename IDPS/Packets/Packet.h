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

    std::string sourceIP;
    std::string destinationIP;
    uint16_t sourcePort;
    uint16_t destinationPort;
    // TCP | UDP
    ProtocolCode_8 protocol;

    // Parsed protocol layers
    EthernetHeader* ethernetHeader = nullptr;
    NetworkHeader* networkHeader = nullptr;
    TransportHeader* transportHeader = nullptr;
};
