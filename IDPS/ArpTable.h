#pragma once

#include "Helper.h"
#include <IPTypes.h>
#include <string>
#include <string_view>
#include <unordered_map>

class ArpTable final
{
public:
    ArpTable() noexcept = default;
    ArpTable(PIP_ADDR_STRING localAddress, std::string_view fileName);
    void updateTable();
    mac getMac(in_addr ipAddr) const noexcept;

private:
    std::unordered_map<uint32_t, mac> m_table;
    std::string m_fileName;
    PIP_ADDR_STRING m_localAddress = nullptr;

    void readFileToTable();
    void writeTableToFile();
};
