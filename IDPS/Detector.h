#pragma once

#include "ArpTable.h"
#include "Packets/Packet.h"
#include <unordered_map>

constexpr auto DOS_THRESHOLD = 100; // packets per second from a single source
constexpr auto ONE_SECOND = 10000000; // in 100-nanosecond intervals

class Detector final
{
private:
    Detector();

    // members
    ArpTable m_arpTable;
	std::unordered_map<uint32_t, std::pair<Timestamp, uint8_t>> m_dosMap; // in_addr is not hashable

public:
    // singelton methods
    ~Detector() noexcept = default;
    static Detector& getInstance() noexcept;
    Detector(const Detector& other) = delete;
    void operator=(const Detector& other) = delete;

    bool isArpReplyLikeTable(const Packet& arpPacket) const;
    static bool isTcpNullScan(const Packet& tcpPacket);
	bool isDoS(const Packet& ipPacket) noexcept;
};
