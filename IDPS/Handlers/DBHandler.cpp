#include "DBHandler.h"
#include <string>
#include <string_view>

sqlite3* DBHandler::db = nullptr;

bool DBHandler::openDB(const char* path) noexcept
{
	return db || sqlite3_open(path, &db) == SQLITE_OK;
}

bool DBHandler::createDB(const char* path)
{
	// verifying that the db file exists and is open
	if (!openDB(path))
		return false; // error value

	// creating Attackers table
	sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS \"Attackers\" ("
					 "\"IP\" TEXT UNIQUE,"
					 "\"MAC\" TEXT NOT NULL UNIQUE,"
					 "PRIMARY KEY(\"MAC\"));", nullptr, nullptr, nullptr);

	// creating Attacks table
	sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS \"Attacks\" ("
					 "\"attack_id\"	INTEGER,"
					 "\"attacker_id\" TEXT NOT NULL);", nullptr, nullptr, nullptr);

	return true;
}

bool DBHandler::closeDB() noexcept
{
	return sqlite3_close(db) == SQLITE_OK;
}

void DBHandler::addAttacker(const std::string& ip, const std::string& mac)
{
	using namespace std::literals;

	const std::string sql = "INSERT INTO Attackers (IP, MAC) VALUES (\""s + ip + "\", \""s + mac + "\");";
	sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
}

void DBHandler::addAttack(const std::string& attacker_id, const attack_type attack_id)
{
	using namespace std::literals;

	const std::string sql = "INSERT INTO Attacks (attacker_id, attack_id) VALUES (\""s + attacker_id + "\", "s + std::to_string(static_cast<short>(attack_id)) + ");";
	sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
}
