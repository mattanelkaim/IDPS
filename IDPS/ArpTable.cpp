#include "ArpTable.h"
#include "Sender.h"
#include <fstream>
#include <iostream>
#include <vector>


ArpTable::ArpTable(PIP_ADDR_STRING localAddress, const std::string_view fileName) :
    m_localAddress(localAddress), m_fileName(fileName)
{
    const std::ifstream checkFile(fileName.data());

    if (!checkFile.good())
    {
        std::ofstream tableFile(fileName.data());
        tableFile << "IP,MAC\n"; // Write CSV header
    }

    this->readFileToTable();
    puts("--------------------------------------");
    this->updateTable();
}


void ArpTable::updateTable()
{
    // First reset all records
    this->m_table.clear();

    // Get all IPs in network
    const std::vector<in_addr> ipAddresses = Sender::mapLocalNetwork(*m_localAddress);
    std::cout << "Total of IPs online: " << ipAddresses.size() << '\n';

    Sleep(5000);

    // Then resolve each IP to its MAC
    for (const in_addr currentIP : ipAddresses)
    {
        const mac currentMAC = Sender::SendARPRequest(currentIP);
        this->m_table.emplace(currentIP.s_addr, currentMAC);
    }

    // TODO REMOVE
    for (const auto& pair : m_table) {
        std::cout << Helper::longToIp(pair.first) << ": " << pair.second.macToString() << '\n';
    }
}


void ArpTable::readFileToTable()
{
    std::ifstream tableFile(m_fileName);

    if (!tableFile.is_open())
        throw std::exception("Cannot open table file!");

    std::string ipStr, macStr;
    std::getline(tableFile, ipStr); // Ignore the header

    // Each time read up to delimiter, then parse line
    while (std::getline(tableFile, ipStr, ','))
    {
        std::getline(tableFile, macStr, '\n');
        //std::cout << "IP is: " << ipStr << " | MAC is: " << macStr << '\n';
        
        const ULONG ipAddr = Helper::ipToLong(ipStr);
        const mac macAddr(macStr);

        m_table.insert_or_assign(ipAddr, macAddr);
    }

    // TODO REMOVE
    for (const auto& pair : m_table) {
        std::cout << Helper::longToIp(pair.first) << ": " << pair.second.macToString() << '\n';
    }
}
