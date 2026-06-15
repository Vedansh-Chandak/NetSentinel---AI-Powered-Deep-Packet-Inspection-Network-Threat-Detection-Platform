#pragma once

#include <cstdint>

class ProtocolStats
{
public:
    void addTCP();
    void addUDP();
    void addICMP();

    void printStats() const;

private:
    uint64_t tcpCount = 0;
    uint64_t udpCount = 0;
    uint64_t icmpCount = 0;
};