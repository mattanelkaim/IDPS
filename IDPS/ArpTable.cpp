#include "ArpTable.h"
#include <fstream>
#include <iostream>


ArpTable::ArpTable(const std::string_view fileName) :
    m_fileName(fileName)
{
    const std::ifstream checkFile(fileName.data());

    if (!checkFile.good())
    {
        std::ofstream tableFile(fileName.data());
        tableFile << "IP,MAC\n"; // Write CSV header
    }

    readFileToTable();
}

void ArpTable::readFileToTable()
{
    std::ifstream tableFile(m_fileName);

    if (!tableFile.is_open())
        throw std::exception("Cannot open table file!");

    int invalidLines = 0;
    std::string ipStr, macStr;
    std::getline(tableFile, ipStr); // Ignore the header

    // Each time read up to delimiter, then parse line
    while (std::getline(tableFile, ipStr, ','))
    {
        std::getline(tableFile, macStr, '\n');
        //std::cout << "IP is: " << ipStr << " | MAC is: " << macStr << '\n';
        
        in_addr ipAddr;
        ipAddr.s_addr = Helper::ipToLong(ipStr);

        const mac macAddr(macStr);

        m_table.insert_or_assign(ipAddr.s_addr, macAddr);
    }

    for (const auto& pair : m_table) {
        std::cout << Helper::longToIp(pair.first) << ": " << pair.second.macToString() << '\n';
    }
}
