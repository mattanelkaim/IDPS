#pragma once

#include <bit>
#include <concepts>
#include <cstdint>
#include <string>

enum ProtocolCode_16 : uint16_t
{
    IPV4 = 0x0800,
    IPV6 = 0x86DD,
    ARP = 0x0806,
};

enum ProtocolCode_8 : uint8_t
{
    TCP = 0x06,
    UDP = 0x11,
};


template <typename T>
concept IntegralOrProtocolCode_16 = std::integral<T> || std::is_same_v<T, ProtocolCode_16>;

// For some reason, all functions MUST BE INLINE
namespace Helper
{
    inline std::string ipToString(const uint32_t ip)
    {
        // Allocate a buffer large enough for "255.255.255.255\0" (16 bytes max)
        char buffer[16];

        // Extract and format directly into the buffer
        std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
                      (ip >> 24) & 0xFF,
                      (ip >> 16) & 0xFF,
                      (ip >> 8) & 0xFF,
                      ip & 0xFF);

        // Return the formatted string (this is optimal)
        return std::string(buffer);
    }

    template <IntegralOrProtocolCode_16 T>
    constexpr T toBigEndian(const T& val) noexcept // constexpr is inherently inline
    {
        if constexpr (std::endian::native == std::endian::big)
            return val;
        else // Swap bytes to Big Endian
        {
            if constexpr (std::is_same_v<T, ProtocolCode_16>)
                return static_cast<T>(std::byteswap(static_cast<uint16_t>(val)));
            else
                return std::byteswap(val);
        }
    }
}
