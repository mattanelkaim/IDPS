#include "Layers.h"
#include <bit>
#include <concepts>
#include <iomanip> // std::setw, std::setfill
#include <stdexcept> // std::runtime_error

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

EthernetHeader::EthernetHeader(const std::vector<uint8_t>& rawData)
{
    if (rawData.size() < sizeof(EthernetHeader)) [[unlikely]]
        throw std::runtime_error("Invalid Ethernet header size");
    
    // Copy raw data into the struct
    *this = *reinterpret_cast<const EthernetHeader*>(rawData.data());
    this->etherType = toBigEndian(this->etherType);
}

std::ostream& operator<<(std::ostream& os, const EthernetHeader& obj)
{
    os << std::hex << std::setfill('0') << "Destination MAC: ";
    for (size_t i = 0; i < 5; ++i)
        os << std::setw(2) << static_cast<int>(obj.dstMAC[i]) << ":";
    os << std::setw(2) << static_cast<int>(obj.dstMAC[5]); // Print last without colon

    os << "\nSource MAC:      ";
    for (size_t i = 0; i < 5; ++i)
        os << std::setw(2) << static_cast<int>(obj.srcMAC[i]) << ":";
    os << std::setw(2) << static_cast<int>(obj.srcMAC[5]); // Print last without colon

    os << "\nEthernet type:   " << std::dec << obj.etherType << '\n';
    return os;
}
