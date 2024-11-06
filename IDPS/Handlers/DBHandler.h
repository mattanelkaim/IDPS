#pragma once

#include <string_view>
#include "../sqlite/sqlite3.h"

enum attack_type
{
	DDOS,
	ARP_SPOOFING,
	DNS_SPOOFING,
	TCP_NULL_SCAN
};

class DBHandler
{
private:
	static sqlite3* db;

public:
	// opening/closing
	static bool openDB(const char* path) noexcept;
	static bool createDB(const char* path) noexcept;
	static bool closeDB() noexcept;

	// updating/inserting
	static void addAttacker(const std::string& ip, const std::string& mac);
	static void addAttack(const std::string& attacker_id, const attack_type attack_id);
};