#include "Packet.h"
#include <iostream>
#include <stdexcept> // std::runtime_error


Packet::Packet(const std::span<const uint8_t> rawData) :
    ethernetHeader(new EthernetHeader(rawData.subspan(0, sizeof(EthernetHeader))))
{
    std::cout << "\n\033[41mEthernet:\033[0m\n" << *ethernetHeader << '\n';
    size_t offset = sizeof(EthernetHeader), layerEnd = offset;

    if (ethernetHeader->etherType == IPV4)
    {
        layerEnd += sizeof(IPv4Header);
        this->ipv4Header = new IPv4Header(rawData.subspan(offset, layerEnd));
        this->sourceIP = Helper::ipToString(ipv4Header->srcIP);
        this->destinationIP = Helper::ipToString(ipv4Header->dstIP);
        std::cout << "\033[42mIP:\033[0m\n" << *ipv4Header << '\n';
    }
    else // Probably IPv6 or ARP
    {
        throw std::runtime_error("Unsupported protocol");
    }

    offset = layerEnd;
    this->protocol = ipv4Header->protocol;
    if (this->protocol == TCP)
    {
        layerEnd += sizeof(TCPHeader);
        this->transportHeader = new TCPHeader(rawData.subspan(offset, layerEnd));
        this->sourcePort = static_cast<TCPHeader*>(transportHeader)->srcPort;
        this->destinationPort = static_cast<TCPHeader*>(transportHeader)->dstPort;
        std::cout << "\033[43mTCP:\033[0m\n" << *static_cast<TCPHeader*>(transportHeader) << '\n';
    }
    else if (this->protocol == UDP)
    {
        layerEnd += sizeof(UDPHeader);
        this->transportHeader = new UDPHeader(rawData.subspan(offset, layerEnd));
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
    delete ipv4Header;
    delete transportHeader;
}
