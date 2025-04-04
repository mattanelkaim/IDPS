#include "Server.h"
#include <iostream>
#include <string>
#include <string_view>

namespace ANSI {
    constexpr std::string_view CYAN = "\033[96m"; // Cyan
    constexpr std::string_view RED = "\033[31;1m"; // Red and bold
    constexpr std::string_view GREEN = "\033[32;1m"; // Green and bold
    constexpr std::string_view BLUE = "\033[34;1m"; // Blue and bold
    constexpr std::string_view NORMAL = "\033[0m"; // Resets back to default
    constexpr std::string_view BLINK = "\033[5m"; // Make the following characters blink
    constexpr std::string_view UP = "\033[A"; // Move up a line
    constexpr std::string_view DOWN = "\033[B"; // Move down a line
}

enum command
{
    EXIT,
    CLS,
    HELP,
    INVALID_COMMAND
};

static constexpr command hashCommands(const std::string_view cmd) noexcept
{
    if (cmd == "exit") return EXIT;
    if (cmd == "cls" || cmd == "clear") return CLS;
    if (cmd == "help") return HELP;
    return INVALID_COMMAND;
}

void Server::run()
{
    std::string userInput;
    command cmd;

    std::cout << ANSI::CYAN << "Welcome to our IDPS Server!\ntype \"help\" to view available commands.\n" << ANSI::NORMAL;
    do
    {
        std::cout << ANSI::BLINK << "> " << ANSI::NORMAL;
        std::cin >> userInput;
        std::cout << ANSI::UP << "\r> " << userInput << ANSI::DOWN << '\r' << std::flush;
        cmd = hashCommands(userInput);
        switch (cmd)
        {
        case CLS:
            system("clear");
            break;
        case INVALID_COMMAND:
            std::cerr << ANSI::RED << "Invalid command\n" << ANSI::NORMAL;
            break;
        case HELP:
            std::cout << ANSI::BLUE << "Helping...\n" << ANSI::NORMAL;
            break;
        case EXIT:
            break;
        }
    } while (cmd != EXIT);

    std::cout << ANSI::GREEN << "\nExited server successfully\n" << ANSI::NORMAL;
}

// Singleton
Server& Server::getInstance() noexcept
{
    static Server instance;
    return instance;
}
