#include "Detector.h"
#include "Distributer.h"
#include "DriverCommunicator.h"
#include "IDPSExceptions.hpp"
#include "PacketExtractor.h"
#include "Sender.h"
#include <iostream>
#include <vector>

void Distributer::run()
{
    in_addr srcIp;
    mac srcMac;
    std::exception_ptr threadException;
    PacketExtractor& packetExtractor = PacketExtractor::getInstance(threadException);
    const Detector& detector = Detector::getInstance();
    const DriverCommunicator& driverCommunicator = DriverCommunicator::getInstance();

    while (true)
    {
        try
        {
            const std::vector<uint8_t> rawPacketData(packetExtractor.getPacket());

            // Checking if the thread threw an exception
            if (threadException)
                std::rethrow_exception(threadException);

            const Packet packet(rawPacketData);

            if (!packet.linkHeader) // nullptr means Null protocol (loopback)
                continue; // Ignore loopback packets

            if (packet.isArpReplyPacket() && detector.isArpReplyLikeTable(packet))
            {
                srcMac = static_cast<EthernetIIHeader*>(packet.linkHeader)->srcMAC;
                std::cout << "ARP Spoofing attack Detected!!!\n";
                std::cout << "Blocking MAC - " << srcMac.macToString() << '\n';
                driverCommunicator.addMacToFirewall(srcMac);
                continue; // if the packet is an ARP, it cant be IPv4/TCP/DNS
            }

            if (!packet.isIPv4Packet())
                continue;

            srcIp = static_cast<IPv4Header*>(packet.networkHeader)->srcIP;
            //if (detector.isDoS(packet))
            //{
            //    std::cout << "DoS attack Detected!!!\n";
            //    std::cout << "Blocking IP - " << Helper::ipToStr(srcIp) << '\n';
            //    driverCommunicator.addIpToFirewall(srcIp.s_addr);
            //}

            if (packet.isTcpPacket() && Detector::isTcpNullScan(packet))
            {
                std::cout << "TCP Null Scan attack Detected!!!\n";
                std::cout << "Blocking IP - " << Helper::ipToStr(srcIp) << '\n';
                driverCommunicator.addIpToFirewall(srcIp.s_addr);
            }

            // TODO: Implement DNS spoofing detection
            if (packet.isDnsPacket())
            {
                const auto dnsHeader = static_cast<DNSMessage*>(packet.applicationData)->header;
                if (dnsHeader.answerCount == 0 &&
                    dnsHeader.authorityCount == 0 &&
                    dnsHeader.additionalCount == 0)
                {
                    // Must be a query
                    puts("-\n-\n-\n-\n-\n-\n-\n-\n-\nSending DNS RESPONSE\n-\n-\n-\n-\n-\n-\n-\n");
                    Sender::sendDNSResponse(packet);
                }
            }
        }
        catch (const MinorException& e)
        {
            std::cerr << "\033[1,9,31,43m*\033[0m " << e.what() << "\n\n";
        }
    }
}


Distributer& Distributer::getInstance() noexcept
{
    static Distributer instance;
    return instance;
}
