#pragma once

// Do NOT sort these includes
#include <bit>
#include <concepts>
#include <cstdint>
#include <string>
#include <string_view>
#include <charconv>
#include <WS2tcpip.h>
#include <IPTypes.h>

constexpr std::string_view INTERFACE_NAME = "Intel(R) Wi-Fi 6 AX201 160MHz";

enum ProtocolCode_16 : uint16_t
{
    IPV4 = 0x0800,
    IPV6 = 0x86DD,
    ARP = 0x0806,
};

enum ProtocolCode_8 : uint8_t
{
    NONE = 0, // Used for ARP packets
    TCP = 0x06,
    UDP = 0x11,
};

enum ArpOpcode : uint16_t
{
    REQUEST = 1,
    REPLY,
    // Other currently useless opcodes until #25
};


struct mac
{
public:
    uint8_t bytes[6] = {0};

    mac() noexcept = default;
    constexpr explicit mac(const std::string_view macStr) noexcept
    {
        const char* currentByte = macStr.data();
        for (int i = 0; i < sizeof(bytes); ++i)
        {
            // Using from_chars because it is constexpr
            std::from_chars(currentByte, currentByte + 2, bytes[i], 16); // Convert hex str to integer
            currentByte += 3; // Skip the ':'
        }
    }

    std::string macToString() const noexcept
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

constexpr mac INVALID_MAC("FF:FF:FF:FF:FF:FF");


// For some reason, all functions MUST BE INLINE
namespace Helper
{
    // Function to convert string IP to unsigned long
    inline ULONG ipToLong(const std::string_view ip) noexcept
    {
        in_addr addr;
        inet_pton(AF_INET, ip.data(), &addr);
        return ntohl(addr.s_addr);
    }

    // Function to convert unsigned long to string IP
    inline std::string longToIp(const ULONG ip) noexcept
    {
        in_addr addr;
        addr.s_addr = htonl(ip);
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);
        return std::string(ipStr);
    }


    template <typename T>
    requires (std::same_as<T, ULONG> || std::same_as<T, std::string>)
    inline T getBroadcastAddress(const IP_ADDR_STRING& ipAddrString) noexcept
    {
        const ULONG ipLong = ipToLong(ipAddrString.IpAddress.String);
        const ULONG maskLong = ipToLong(ipAddrString.IpMask.String);

        // Calculate the broadcast address
        const ULONG broadcastLong = ipLong | (~maskLong);

        if constexpr (std::same_as<T, std::string>)
            return longToIp(broadcastLong);
        else
            return broadcastLong;
    }

    inline ULONG getMinAddress(const IP_ADDR_STRING& ipAddrString) noexcept
    {
        const ULONG ipLong = ipToLong(ipAddrString.IpAddress.String);
        const ULONG maskLong = ipToLong(ipAddrString.IpMask.String);

        // Calculate the minimum address
        const ULONG min = (ipLong & maskLong) | 1;

        return min;
    }


    template <typename T>
    requires (std::integral<T> || std::same_as<T, ProtocolCode_16> || std::same_as<T, ArpOpcode>)
    constexpr T toBigEndian(const T& val) noexcept // constexpr is inherently inline
    {
        if constexpr (std::endian::native == std::endian::big)
            return val;
        else // Swap bytes to Big Endian
        {
            if constexpr (std::integral<T>)
                return std::byteswap(val);
            else
                return static_cast<T>(std::byteswap(static_cast<uint16_t>(val)));
        }
    }
} // namespace Helper
