#pragma once

#include <format>
#include <stdexcept>

class FatalException : public std::runtime_error
{
public:
    explicit FatalException(const char* message) : std::runtime_error(message) {}
};

class FatalWinException : public FatalException
{
public:
    explicit FatalWinException(const char* message, uint32_t code) : FatalException(std::format("({}) - {}", code, message).c_str()) {}
};

class MinorException : public std::runtime_error
{
public:
    explicit MinorException(const char* message) : std::runtime_error(message) {}
};
