#include "Layers.h"
#include <cstring> // std::memcpy
#include <stdexcept> // std::runtime_error

EthernetHeader::EthernetHeader(const std::vector<uint8_t>& rawData)
{
    if (rawData.size() < sizeof(EthernetHeader))
        throw std::runtime_error("Invalid Ethernet header size");

    std::memcpy(this->dstMAC, rawData.data(), 6);
    std::memcpy(this->srcMAC, rawData.data() + 6, 6);
    // Use bitwise shift and OR to combine the two bytes a single 16-bit
    this->etherType = static_cast<ProtocolCode>((rawData[12] << 8) | rawData[13]);
}
