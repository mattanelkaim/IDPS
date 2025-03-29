#pragma once

#include <sqlite3.h>
#include <string_view>
#include <stdint.h>

enum attack_type : uint8_t
{
    DDOS,
    ARP_SPOOFING,
    DNS_SPOOFING,
    TCP_NULL_SCAN,
};

class DBHandler final
{
private:
    inline static sqlite3* m_db = nullptr;

public:
    // opening/closing
    static bool openDB(const char* path) noexcept;
    static bool createDB(const char* path) noexcept;
    static bool closeDB() noexcept;

    // updating/inserting
    static void addAttacker(std::string_view ip, std::string_view mac);
    static void addAttack(std::string_view attacker_id, attack_type attack_id);
    
    // Helper functions
    static void runQuery(std::string_view query);
};
