#pragma once

#include "../Helper.h"
#include "Layers.h"
#include <span>

using Timestamp = uint64_t; // amount of 100-nanosecond intervals since last system startup

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
	in_addr getSrcIp() const noexcept;
};
