#pragma once

#include <string>
#include <cstdint>

struct Rule
{
    std::string name;
    uint16_t port;
    std::string severity;
};