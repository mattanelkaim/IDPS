#pragma once


#include <bit>
#include <charconv>
#include <concepts>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
// Do NOT sort these includes
#include <WS2tcpip.h>
#include <IPTypes.h>

constexpr std::string_view INTERFACE_NAME_LAP = "Intel(R) Wi-Fi 6 AX201 160MHz";
constexpr std::string_view INTERFACE_NAME_PC = "Realtek PCIe GbE Family Controller";
constexpr std::string_view INTERFACE_NAME_VM = "Intel(R) PRO/1000 MT Desktop Adapter";
constexpr std::string_view INTERFACE_NAME_DBG = "Microsoft Kernel Debug Network Adapter";

enum ProtocolCode_32 : uint32_t
{
    NULL_IPV4 = 0x0002,
};

enum ProtocolCode_16 : uint16_t
{
    IPV4 = 0x0800,
    IPV6 = 0x86DD,
    ARP = 0x0806,
};

enum ProtocolCode_8 : uint8_t
{
    NONE = 0, // Used for ARP packets
    ETHERNET = 1, // Arbitrary
    LOOPBACK = 2, // Arbitrary
    TCP = 0x06,
    UDP = 0x11,
};

enum ArpOpcode : uint16_t
{
    REQUEST = 1,
    REPLY,
    // Other currently useless opcodes until #25
};

// General concept to help with type checking
template <typename T, typename... U>
concept IsAnyOf = (std::same_as<T, U> || ...);


struct mac
{
public:
    uint8_t bytes[6] = {0};

    mac() noexcept = default;
    constexpr explicit mac(std::string_view macStr) noexcept
    {
        const char* currentByte = macStr.data();
        for (uint8_t i = 0; i < sizeof(bytes); ++i)
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
        return {buffer};
    }

    bool operator==(const mac& other) const noexcept
    {
        return !memcmp(bytes, other.bytes, sizeof(bytes));
    }
};


// For some reason, all functions MUST BE INLINE
namespace Helper
{
    template <typename T>
    requires (std::integral<T> || std::is_enum_v<T>)
    constexpr T byteswap(T val) noexcept // constexpr is inherently inline
    {
        if constexpr (std::integral<T>)
            return std::byteswap(val);
        else // Enum - cast to underlying (integral) type
            return static_cast<T>(std::byteswap(static_cast<std::underlying_type_t<T>>(val)));
    }


    // Function to convert string IP to unsigned long
    inline in_addr strToIp(std::string_view ip) noexcept
    {
        in_addr addr;
        inet_pton(AF_INET, ip.data(), &addr);
        addr.s_addr = byteswap(addr.s_addr);
        return addr;
    }

    // Function to convert unsigned long to string IP
    template <IsAnyOf<ULONG, in_addr> T>
    constexpr std::string ipToStr(T ip) noexcept
    {
        if constexpr (std::same_as<T, in_addr>)
            ip.s_addr = byteswap(ip.s_addr);
        else // ULONG
            ip = byteswap(ip);

        char ipStr[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &ip, ipStr, INET_ADDRSTRLEN);
        return {ipStr};
    }


    template <IsAnyOf<ULONG, std::string> T>
    inline T getBroadcastAddress(const IP_ADDR_STRING& ipAddrString) noexcept
    {
        const ULONG ipLong = strToIp(ipAddrString.IpAddress.String).s_addr;
        const ULONG maskLong = strToIp(ipAddrString.IpMask.String).s_addr;

        // Calculate the broadcast address
        const ULONG broadcastLong = ipLong | (~maskLong);

        if constexpr (std::same_as<T, std::string>)
            return ipToStr(broadcastLong);
        else
            return broadcastLong;
    }

    inline ULONG getMinAddress(const IP_ADDR_STRING& ipAddrString) noexcept
    {
        const ULONG ipLong = strToIp(ipAddrString.IpAddress.String).s_addr;
        const ULONG maskLong = strToIp(ipAddrString.IpMask.String).s_addr;

        // Calculate the minimum address
        return (ipLong & maskLong) | 1;
    }

    consteval sockaddr_in getLocalhostDnsAddr() noexcept
    {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = byteswap(53Ui16); // DNS port
        addr.sin_addr.S_un.S_un_b = {127, 0, 0, 1}; // Localhost

        return addr;
    }


    constexpr void insertWordToBytes(std::vector<uint8_t>& vec, uint16_t word) noexcept
    {
        vec.insert(vec.end(), {
            static_cast<uint8_t>(word >> 8),
            static_cast<uint8_t>(word)
        });
    }

    constexpr void insertDwordToBytes(std::vector<uint8_t>& vec, uint32_t dword) noexcept
    {
        vec.insert(vec.end(), {
            static_cast<uint8_t>(dword >> 24),
            static_cast<uint8_t>(dword >> 16),
            static_cast<uint8_t>(dword >> 8),
            static_cast<uint8_t>(dword)
        });
    }
} // namespace Helper
