#pragma once

#include "Helper.h"
#include <string>
#include <string_view>
#include <unordered_map>

class ArpTable
{
public:
    ArpTable(std::string_view fileName);

private:
    std::unordered_map<unsigned long, mac> m_table;
    std::string m_fileName;

    void readFileToTable();
};
