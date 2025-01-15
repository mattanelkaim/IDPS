#pragma once

#include "Helper.h"
#include <IPTypes.h>
#include <string>
#include <string_view>
#include <unordered_map>

class ArpTable
{
public:
    ArpTable(PIP_ADDR_STRING localAddress, std::string_view fileName);
    void updateTable();

private:
    std::unordered_map<unsigned long, mac> m_table;
    std::string m_fileName;
    PIP_ADDR_STRING m_localAddress;

    void readFileToTable();
};
