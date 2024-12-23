#pragma once

//#include "Packets/Layers.h"
#include <bit>
#include <concepts>
#include <cstdint>
#include <string>

enum ProtocolCode : uint16_t
{
    IPV4 = 0x0800,
    IPV6 = 0x86DD,
    TCP = 0x06,  // TODO ERROR MUST BE 1 BYTE ONLY
    UDP = 0x11,
    ARP = 0x0806,
};

//namespace Helper
//{
//    std::string ipToString(const uint32_t ip) noexcept
//    {
//        // Allocate a buffer large enough for "255.255.255.255\0" (16 bytes max)
//        char buffer[16];
//
//        // Extract and format directly into the buffer
//        std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
//                      (ip >> 24) & 0xFF,
//                      (ip >> 16) & 0xFF,
//                      (ip >> 8) & 0xFF,
//                      ip & 0xFF);
//
//        // Return the formatted string (this is optimal)
//        return std::string(buffer);
//    }
//}


template <typename T>
concept IntegralOrProtocolCode = std::integral<T> || std::is_same_v<T, ProtocolCode>;

template <IntegralOrProtocolCode T>
constexpr T toBigEndian(const T& val) noexcept
{
    if constexpr (std::endian::native == std::endian::big)
        return val;
    else // Swap bytes to Big Endian
    {
        if constexpr (std::is_same_v<T, ProtocolCode>)
            return static_cast<T>(std::byteswap(static_cast<uint16_t>(val)));
        else
            return std::byteswap(val);
    }
}
