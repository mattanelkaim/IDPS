#pragma once

#include "ArpTable.h"
#include "Packets/Packet.h"
#include <unordered_map>

constexpr auto DOS_THRESHOLD = 100;
constexpr auto ONE_SECOND = 10000000; // in 100-nanosecond intervals

class Detector final
{
private:
    Detector();

    // members
    ArpTable m_arpTable;
	std::unordered_map<in_addr, std::pair<Timestamp, uint8_t>> m_dosMap;

public:
    // singelton methods
    ~Detector() noexcept = default;
    static Detector& getInstance() noexcept;
    Detector(const Detector& other) = delete;
    void operator=(const Detector& other) = delete;

    bool isArpReplyLikeTable(const Packet& arpPacket) const;
    static bool isTcpNullScan(const Packet& tcpPacket);
	bool isDoS(const Packet& ipPacket);
};
