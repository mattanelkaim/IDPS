#include "Distributer.h"
#include "PacketExtractor.h"
#include "Detector.h"
#include "DriverCommunicator.h"
#include <iostream>

Distributer& Distributer::getInstance() noexcept
{
    static Distributer instance;
    return instance;
}

void Distributer::run() const
{
    Detector& detector = Detector::getInstance();
    DriverCommunicator& driverCommunicator = DriverCommunicator::getInstance();
    in_addr srcIp;
    mac srcMac;

    while (true)
    {
        try
        {
            Packet packet(PacketExtractor::getInstance().getPacket());

            if (packet.isArpReplyPacket() && detector.isArpReplyLikeTable(packet))
            {
                srcMac = packet.ethernetHeader->srcMAC;
                std::cout << "ARP Spoofing attack Detected!!!" << std::endl;
                std::cout << "Blocking MAC - " << srcMac.macToString();
                driverCommunicator.addMacToFirewall(srcMac);
                continue; // if the packet is an ARP, it cant be IPv4/TCP/DNS
            }

            if (!packet.isIPv4Packet())
                continue;

            srcIp = reinterpret_cast<IPv4Header*>(packet.networkHeader)->srcIP;
            if (detector.isDoS(packet))
            {
                std::cout << "DoS attack Detected!!!" << std::endl;
                std::cout << "Blocking IP - " << Helper::ipToStr(srcIp);
                driverCommunicator.addIpToFirewall(srcIp.s_addr);
            }

            if (packet.isTcpPacket() && detector.isTcpNullScan(packet))
            {
                std::cout << "TCP Null Scan attack Detected!!!" << std::endl;
                std::cout << "Blocking IP - " << Helper::ipToStr(srcIp);
                driverCommunicator.addIpToFirewall(srcIp.s_addr);
            }

            // TODO: Implement DNS spoofing detection
            /*if (packet.isDnsPacket() && detector.isDNSSpoofing(packet))
            {
                
            }*/
        }
        catch (const std::runtime_error& e)
        {
            std::cerr << e.what() << '\n';
            continue;
        }
    }
}
