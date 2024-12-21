#include "Packet.h"

std::string ipToString(const uint32_t ip) noexcept
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


Packet::Packet(const IPv4Header& ipv4, const TransportHeader& transport) noexcept :
    sourceIP(ipToString(ipv4.sourceAddress)),
    destinationIP(ipToString(ipv4.destinationAddress)),
    sourcePort(transport.sourcePort),
    destinationPort(transport.destinationPort),
    protocol(ipv4.protocol)
{}
