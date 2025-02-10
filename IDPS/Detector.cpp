#include "Detector.h"
#include "Sender.h"
#include <stdexcept>


Detector::Detector()
{
    IP_ADDR_STRING localIP;
    if (!Sender::GetLocalIpAddress(INTERFACE_NAME1.data(), &localIP))
        throw std::exception("Failed to get local IP address!\n");

    m_arpTable = ArpTable(&localIP, "ARP.csv");
    //m_arpTable.updateTable(); // TODO ENABLE IN PRODUCTION
}


bool Detector::isArpReplyLikeTable(const Packet& arpPacket) const
{
    if (arpPacket.ethernetHeader->etherType != ARP)
        throw std::invalid_argument("Packet does not have an ARP header!");
    
    const ArpHeader* arpHeader = reinterpret_cast<ArpHeader*>(arpPacket.networkHeader);
    if (arpHeader->opcode != REPLY)
        throw std::invalid_argument("ARP packet must be a reply!");

    // TODO define behavior if MAC is not in table
    return arpHeader->senderMAC == m_arpTable.getMac(arpHeader->senderIP);
}

bool Detector::isTcpNullScan(const Packet& tcpPacket)
{
    if (tcpPacket.transportProtocol != TCP)
        throw std::invalid_argument("Packet does not use the TCP protocol!");

    return !reinterpret_cast<TCPHeader*>(tcpPacket.transportHeader)->flags; // return true if all flags are unset
}

bool Detector::isDoS(const Packet& ipPacket)
{
    // Validate that the packet uses IPv4
    if (ipPacket.ethernetHeader->etherType != IPV4)
        throw std::invalid_argument("Packet does not use the IPv4 protocol!");

    const uint32_t srcIp = reinterpret_cast<IPv4Header*>(ipPacket.networkHeader)->srcIP.s_addr;

    // Inserting IP if it is new (insert with counter=1)
    if (!m_dosMap.contains(srcIp))
        m_dosMap.insert({ srcIp, { ipPacket.timestamp, 1 } });

    // 100 packets per second from a single source is considered a DoS attack
    else if ((ipPacket.timestamp - m_dosMap[srcIp].first) < ONE_SECOND)
    {
        if (++std::get<1>(m_dosMap[srcIp]) >= DOS_THRESHOLD)
            return true;

        // resetting the counter if the last packet was more than a second ago
        else
            m_dosMap[srcIp] = { ipPacket.timestamp, 1 };
    }

    return false;
}


// SINGLETON METHODS


Detector& Detector::getInstance() noexcept
{
    static Detector instance;
    return instance;
}
