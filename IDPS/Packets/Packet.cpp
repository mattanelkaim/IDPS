#include "Packet.h"
#include <iostream>
#include <stdexcept> // std::runtime_error


Packet::Packet(const std::span<const uint8_t> rawData) :
    ethernetHeader(new EthernetHeader(rawData.subspan(0, sizeof(EthernetHeader))))
{
    std::cout << "\n\033[41mEthernet:\033[0m\n" << *ethernetHeader << '\n';
    size_t offset = sizeof(EthernetHeader);

    if (ethernetHeader->etherType == IPV4)
    {
        this->networkHeader = new IPv4Header(rawData.subspan(offset, sizeof(IPv4Header)));
        offset += sizeof(IPv4Header);
        this->sourceIP = Helper::longToIp(static_cast<IPv4Header*>(networkHeader)->srcIP);
        this->destinationIP = Helper::longToIp(static_cast<IPv4Header*>(networkHeader)->dstIP);
        this->protocol = static_cast<IPv4Header*>(networkHeader)->protocol;
        std::cout << "\033[42mIP:\033[0m\n" << *static_cast<IPv4Header*>(networkHeader) << '\n';
    }
    else if (ethernetHeader->etherType == ARP)
    {
        this->networkHeader = new ArpHeader(rawData.subspan(offset, sizeof(ArpHeader)));
        offset += sizeof(ArpHeader);
        this->sourceIP = "";
        this->destinationIP = "";
        this->protocol = NONE;
        this->sourcePort = 0;
        this->destinationPort = 0;
        std::cout << "\033[42mIP:\033[0m\n" << *static_cast<ArpHeader*>(networkHeader) << '\n';
        return; // No transport layer!
    }
    else // Probably IPv6
    {
        throw std::runtime_error("Unsupported protocol");
    }

    if (this->protocol == TCP)
    {
        this->transportHeader = new TCPHeader(rawData.subspan(offset, sizeof(TCPHeader)));
        offset += sizeof(TCPHeader);
        this->sourcePort = static_cast<TCPHeader*>(transportHeader)->srcPort;
        this->destinationPort = static_cast<TCPHeader*>(transportHeader)->dstPort;
        std::cout << "\033[43mTCP:\033[0m\n" << *static_cast<TCPHeader*>(transportHeader) << '\n';
    }
    else if (this->protocol == UDP)
    {
        this->transportHeader = new UDPHeader(rawData.subspan(offset, sizeof(UDPHeader)));
        offset += sizeof(UDPHeader);
        this->sourcePort = static_cast<UDPHeader*>(transportHeader)->srcPort;
        this->destinationPort = static_cast<UDPHeader*>(transportHeader)->dstPort;
        std::cout << "\033[43mUDP:\033[0m\n" << *static_cast<UDPHeader*>(transportHeader) << '\n';
    }
    else
    {
        throw std::runtime_error("Unsupported transport protocol");
    }
}

Packet::~Packet()
{
    delete ethernetHeader;
    delete networkHeader;
    delete transportHeader;
}
