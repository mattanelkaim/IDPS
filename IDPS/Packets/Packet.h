#pragma once

#include "Layers.h"
#include <string>

class Packet
{
public:
    Packet(const IPv4Header& ipv4, const TransportHeader& transport) noexcept;

    std::string sourceIP;
    std::string destinationIP;
    const uint16_t sourcePort;
    const uint16_t destinationPort;
    // TCP | UDP
    const ProtocolCode protocol;

    // Parsed protocol layers
    EthernetHeader* ethernetHeader = nullptr;
    IPv4Header* ipv4Header = nullptr;
    TransportHeader* transportHeader = nullptr;
};
