#pragma once

#include "ArpTable.h"
#include "Packets/Packet.h"
#include <unordered_map>

constexpr auto DOS_THRESHOLD = 100; // packets per second from a single source
constexpr auto ONE_SECOND = 10'000'000; // in 100-nanosecond intervals

class Detector final
{
private:
    Detector();

    // Members
    ArpTable m_arpTable;
    // {in_addr: (Timestamp, counter)}
    std::unordered_map<uint32_t, std::pair<Timestamp, uint8_t>> m_dosMap; // in_addr is not hash-able

public:
    // Singleton methods
    ~Detector() noexcept = default;
    inline static Detector& getInstance() noexcept;
    Detector(const Detector& other) = delete;
    void operator=(const Detector& other) = delete;

    bool isArpReplyLikeTable(const Packet& arpPacket) const noexcept;
    static bool isTcpNullScan(const Packet& tcpPacket) noexcept;
    bool isDoS(const Packet& ipPacket) noexcept;
};
