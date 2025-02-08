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

bool Detector::isDNSSpoofing(const Packet& dnsPacket)
{

    // validate ip.src to be a trusted DNS address
    // send the same DNS request *OVER HTTPS* and validate the responses

    return false;
}


// SINGLETON METHODS


Detector& Detector::getInstance() noexcept
{
    static Detector instance;
    return instance;
}
