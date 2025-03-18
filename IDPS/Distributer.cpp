#include "Detector.h"
#include "Distributer.h"
#include "DriverCommunicator.h"
#include "IDPSExceptions.hpp"
#include "PacketExtractor.h"
#include <iostream>
#include <vector>

void Distributer::run() const
{
    in_addr srcIp;
    mac srcMac;
    std::exception_ptr threadException;
    PacketExtractor& packetExtractor = PacketExtractor::getInstance(threadException);
    Detector& detector = Detector::getInstance();
    DriverCommunicator& driverCommunicator = DriverCommunicator::getInstance();

    while (true)
    {
        try
        {
            const std::vector<uint8_t> rawPacketData(packetExtractor.getPacket());

            // Checking if the thread threw an exception
            if (threadException)
                std::rethrow_exception(threadException);

            Packet packet(rawPacketData);

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
        catch (const MinorException& e)
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
