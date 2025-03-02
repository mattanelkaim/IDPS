#pragma once

#include <stdexcept>


class FatalException : public std::runtime_error
{
public:
    explicit FatalException(const char* message) : std::runtime_error(message) {}
};

class MinorException : public std::runtime_error
{
public:
    explicit MinorException(const char* message) : std::runtime_error(message) {}
};
