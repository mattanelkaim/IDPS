#include "DBHandler.h"
#include <string>

using namespace std::literals;

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

void DBHandler::addAttacker(const std::string& ip, const std::string& mac)
{
    const std::string sql = "INSERT INTO Attackers (IP, MAC) VALUES (\""s + ip + "\", \""s + mac + "\")";
    runQuery(sql);
}

void DBHandler::addAttack(const std::string& attacker_id, attack_type attack_id)
{
    const std::string sql = "INSERT INTO Attacks (attacker_id, attack_id) VALUES (\""s + attacker_id + "\", "s + std::to_string(static_cast<int16_t>(attack_id)) + ")";
    runQuery(sql);
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
