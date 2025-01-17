#pragma once

#include "ArpTable.h"
#include "Packets/Packet.h"

class Detector final
{
private:
    Detector();

    // members
    ArpTable m_arpTable;

public:
    // singelton methods
    ~Detector() noexcept = default;
    static Detector& getInstance() noexcept;
    Detector(const Detector& other) = delete;
    void operator=(const Detector& other) = delete;

    bool isArpReplyLikeTable(const Packet& arpPacket);
};
