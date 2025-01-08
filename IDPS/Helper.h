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


struct mac
{
public:
    uint8_t bytes[6] = {0};

    inline std::string macToString() const noexcept
    {
        char buffer[18] = {0}; // 12 hex digits + 5 colons + 1 null terminator
        sprintf_s(buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
                  bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
        return std::string(buffer);
    }

    // Define a conversion to represent in an integer form
    constexpr operator uint64_t() const noexcept
    {
        // Not using std::memcpy to make the function constexpr
        uint64_t mac_as_uint64 = 0;
        for (int8_t i = sizeof(bytes) - 1; i >= 0; --i)
            mac_as_uint64 |= static_cast<uint64_t>(this->bytes[i]) << (8 * (sizeof(bytes) - 1 - i));
        return mac_as_uint64;
    }
};


// For some reason, all functions MUST BE INLINE
namespace Helper
{
    inline std::string ipToString(const uint32_t ip)
    {
        // Allocate a buffer large enough for "255.255.255.255\0" (16 bytes max)
        char buffer[16];

        // Extract and format directly into the buffer
        sprintf_s(buffer, "%u.%u.%u.%u",
                      (ip >> 24) & 0xFF,
                      (ip >> 16) & 0xFF,
                      (ip >> 8) & 0xFF,
                      ip & 0xFF);

        // Return the formatted string (this is optimal)
        return std::string(buffer);
    }


    template <typename T>
    concept IntegralOrProtocolCode_16 = std::integral<T> || std::is_same_v<T, ProtocolCode_16>;

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
} // namespace Helper
