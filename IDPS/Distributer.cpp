#include "Distributer.h"
#include "PacketExtractor.h"
#include "Detector.h"
#include <iostream>

Distributer& Distributer::getInstance() noexcept
{
    static Distributer instance;
    return instance;
}

void Distributer::run() const
{
    Detector& detector = Detector::getInstance();
    while (true)
    {
        try
        {
            Packet packet(PacketExtractor::getInstance().getPacket());
            if (detector.isArpReplyLikeTable(packet))
            {
                std::cout << "ARP reply-like table detected!" << std::endl;
            }
            else if (detector.isTcpNullScan(packet))
            {
                std::cout << "TCP NULL scan detected!" << std::endl;
            }
            else if (detector.isDoS(packet))
            {
                std::cout << "DoS detected!" << std::endl;
            }
        }
        catch (...) // Catch all exceptions
        {
            std::cout << "Could not parse!!!!!!!!!!!!!!!" << std::endl;
        }
    }
}

bool Distributer::isArpPacket(const Packet& packet) noexcept
{
    return packet.ethernetHeader->etherType == ARP;
}
