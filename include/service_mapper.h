#pragma once

#include <string>
#include <cstdint>

class ServiceMapper
{
public:
    static std::string getService(
        uint16_t port
    );
};