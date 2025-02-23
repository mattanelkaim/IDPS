#pragma once

#include <stdexcept>


class FatalException : public std::runtime_error
{
public:
    explicit FatalException(const std::string& message) : std::runtime_error(message) {}
};

class MinorException : public std::runtime_error
{
public:
    explicit MinorException(const std::string& message) : std::runtime_error(message) {}
};
