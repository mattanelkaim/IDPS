#include "Detector.h"
#include "Sender.h"
#include <iostream>


Detector::Detector()
{
    IP_ADDR_STRING localIP;
    if (!Sender::GetLocalIpAddress(INTERFACE_NAME.data(), &localIP))
        throw std::exception("Failed to get local IP address!\n");

    m_arpTable = ArpTable(&localIP, "ARP.csv");
    //m_arpTable.updateTable(); // TODO ENABLE IN PRODUCTION
}


bool Detector::isArpReplyLikeTable(const Packet& packet)
{
    if (packet.ethernetHeader->etherType != ARP)
        throw std::invalid_argument("Packet does not have an ARP header!");
    
    const ArpHeader* arpHeader = reinterpret_cast<ArpHeader*>(packet.networkHeader);
    if (arpHeader->opcode != REPLY)
        throw std::invalid_argument("ARP packet must be a reply!");

    return true;
}


// SINGLETON METHODS


Detector& Detector::getInstance() noexcept
{
    static Detector instance;
    return instance;
}
