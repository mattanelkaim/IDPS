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

    readFileToTable();
}


void ArpTable::updateTable()
{
    // First reset all records
    this->m_table.clear();

    // Get all IPs in network
    const std::vector<in_addr> ipAddresses = Sender::mapLocalNetwork(*m_localAddress);
    std::cout << "\nOnline IPs:" << '\n';

    // Then resolve each IP to its MAC
    for (const in_addr currentIP : ipAddresses)
    {
        std::cout << Helper::longToIp(currentIP.s_addr) << '\n';
        const mac currentMAC = Sender::SendARPRequest(currentIP);
        this->m_table.emplace(currentIP.s_addr, currentMAC);
    }

    this->writeTableToFile();
}


mac ArpTable::getMac(const in_addr ipAddr)
{
    const auto it = m_table.find(ipAddr.s_addr);
    return (it == m_table.cend()) ? invalidMac : it->second;
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
        
        const ULONG ipAddr = Helper::ipToLong(ipStr);
        const mac macAddr(macStr);

        m_table.insert_or_assign(ipAddr, macAddr);
    }
}


void ArpTable::writeTableToFile()
{
    // Open table file and delete its previous contents
    std::ofstream tableFile(m_fileName, std::ios_base::trunc);

    tableFile << "IP,MAC\n"; // Insert CSV header

    // Write each IP&MAC pair as a new line
    for (const auto& [ip, mac] : m_table)
        tableFile << Helper::longToIp(ip) << ',' << mac.macToString() << '\n';
}
