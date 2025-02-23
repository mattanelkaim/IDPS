#include "Detector.h"
#include "Distributer.h"
#include "DriverCommunicator.h"
#include "PacketExtractor.h"
#include <iostream>

void Distributer::run() const
{
    Detector& detector = Detector::getInstance();
    DriverCommunicator& driverCommunicator = DriverCommunicator::getInstance();
    // Initialize frequently used variables only once
    in_addr srcIp;
    mac srcMac;

    while (true)
    {
        try
        {
            Packet packet(PacketExtractor::getInstance().getPacket());

            if (!packet.linkHeader) // nullptr means Null protocol (loopback)
                continue; // Ignore loopback packets

            if (packet.isArpReplyPacket() && detector.isArpReplyLikeTable(packet))
            {
                srcMac = reinterpret_cast<EthernetHeader*>(packet.linkHeader)->srcMAC;
                std::cout << "ARP Spoofing attack Detected!!!\n";
                std::cout << "Blocking MAC - " << srcMac.macToString() << '\n';
                driverCommunicator.addMacToFirewall(srcMac);
                continue; // if the packet is an ARP, it cant be IPv4/TCP/DNS
            }

            if (!packet.isIPv4Packet())
                continue;

            srcIp = reinterpret_cast<IPv4Header*>(packet.networkHeader)->srcIP;
            if (detector.isDoS(packet))
            {
                std::cout << "DoS attack Detected!!!\n";
                std::cout << "Blocking IP - " << Helper::ipToStr(srcIp) << '\n';
                driverCommunicator.addIpToFirewall(srcIp.s_addr);
            }

            if (packet.isTcpPacket() && detector.isTcpNullScan(packet))
            {
                std::cout << "TCP Null Scan attack Detected!!!\n";
                std::cout << "Blocking IP - " << Helper::ipToStr(srcIp) << '\n';
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
        }
    }
}


Distributer& Distributer::getInstance() noexcept
{
    static Distributer instance;
    return instance;
}
