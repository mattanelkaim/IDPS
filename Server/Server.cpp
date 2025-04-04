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
    constexpr std::string_view UP = "\r\033[A"; // Move to the start of the upper line
    constexpr std::string_view DOWN = "\r\033[B"; // Move to the start of the bottom line
    constexpr std::string_view CLS = "\033[3J\033[H\033[2J"; // clears the screen and output buffer
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
    command cmd = INVALID_COMMAND;

    std::cout << ANSI::CYAN << "Welcome to our IDPS Server!\nType \"help\" to view available commands.\n" << ANSI::NORMAL;
    do
    {
        std::cout << ANSI::BLINK << "> " << ANSI::NORMAL;
        std::cin >> userInput;
        std::cin.ignore(__INT_MAX__, '\n'); // discarding everything inputted after the first word
        std::cout << ANSI::UP << "> " << ANSI::DOWN; // remove blinking from previous line
        cmd = hashCommands(userInput);
        switch (cmd)
        {
        case CLS:
            std::cout << ANSI::CLS; // Do NOT use system("clear") here!
            break;
        case INVALID_COMMAND:
            std::cerr << ANSI::RED << "Invalid command\n" << ANSI::NORMAL;
            break;
        case HELP:
            std::cout << ANSI::BLUE << "Available commands:\n\tcls/clear - clear the screen\n\thelp - show available commands\n\texit - terminate the server\n" << ANSI::NORMAL;
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
