#include "Detector.h"
#include "Sender.h"


Detector::Detector()
{
    IP_ADDR_STRING localIP;
    if (!Sender::GetLocalIpAddress(INTERFACE_NAME4.data(), &localIP))
        throw std::exception("Failed to get local IP address!\n");

    m_arpTable = ArpTable(&localIP, "ARP.csv");
    //m_arpTable.updateTable(); // TODO ENABLE IN PRODUCTION
}


bool Detector::isArpReplyLikeTable(const Packet& arpPacket) const noexcept
{
    const ArpHeader* arpHeader = reinterpret_cast<ArpHeader*>(arpPacket.networkHeader);

    // TODO define behavior if MAC is not in table
    return arpHeader->senderMAC == m_arpTable.getMac(arpHeader->senderIP);
}

bool Detector::isTcpNullScan(const Packet& tcpPacket) noexcept
{
    return !reinterpret_cast<TCPHeader*>(tcpPacket.transportHeader)->flags; // return true if all flags are unset
}

bool Detector::isDoS(const Packet& ipPacket) noexcept
{
    const uint32_t srcIp = reinterpret_cast<IPv4Header*>(ipPacket.networkHeader)->srcIP.s_addr;

    // Inserting IP if it is new (insert with counter=1)
    if (!m_dosMap.contains(srcIp))
    {
        m_dosMap[srcIp] = { ipPacket.timestamp, 1 };
        return false;
    }

    // 100 packets per second from a single source is considered a DoS attack
    else if ((ipPacket.timestamp - m_dosMap[srcIp].first) > ONE_SECOND)
    {
        // Reset counter
        m_dosMap[srcIp] = { ipPacket.timestamp, 1 };
        return false;
    }

    // Incrementing the counter and checking if the threshold was reached
    return (++std::get<1>(m_dosMap[srcIp]) >= DOS_THRESHOLD);
}


// SINGLETON METHODS


Detector& Detector::getInstance()
{
    static Detector instance;
    return instance;
}
