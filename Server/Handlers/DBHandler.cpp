#include "DBHandler.h"
#include <format>

bool DBHandler::openDB(const char* path) noexcept
{
    // Skip if already open, else try to open and return whether successful
    return m_db || (sqlite3_open(path, &m_db) == SQLITE_OK);
}

bool DBHandler::createDB(const char* path) noexcept
{
    // verifying that the db file exists and is open
    if (!openDB(path))
        return false; // error value

    // creating Attackers table
    runQuery("CREATE TABLE IF NOT EXISTS Attackers ("
             "IP TEXT UNIQUE,"
             "MAC TEXT NOT NULL UNIQUE,"
             "PRIMARY KEY(MAC))");

    // creating Attacks table
    runQuery("CREATE TABLE IF NOT EXISTS Attacks ("
             "attack_id INTEGER,"
             "attacker_id TEXT NOT NULL)");

    return true;
}

bool DBHandler::closeDB() noexcept
{
    return sqlite3_close(m_db) == SQLITE_OK;
}

void DBHandler::addAttacker(std::string_view ip, std::string_view mac)
{
    runQuery(std::format(R"(INSERT INTO Attackers (IP, MAC) VALUES ("{}", "{}"))", ip, mac));
}

void DBHandler::addAttack(std::string_view attacker_id, attack_type attack_id)
{
    runQuery(std::format(R"(INSERT INTO Attacks (attacker_id, attack_id) VALUES ("{}", "{}"))", attacker_id, static_cast<uint8_t>(attack_id)));
}


// HELPER FUNCTIONS


void DBHandler::runQuery(std::string_view query)
{
    char* sqlErrorMsg = nullptr; // Will be set by sqlite3_exec() if an error occurs

    if (sqlite3_exec(m_db, query.data(), nullptr, nullptr, &sqlErrorMsg) != SQLITE_OK)
    {
        puts(sqlErrorMsg);
        sqlite3_free(sqlErrorMsg);
    }
}
