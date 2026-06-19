#pragma once

#include <cstdint>

class ProtocolStats
{
public:
    void addTCP();
    void addUDP();
    void addICMP();

    void printStats() const;

    uint64_t getTCP() const
    {
        return tcpCount;
    }

    uint64_t getUDP() const
    {
        return udpCount;
    }

    uint64_t getICMP() const
    {
        return icmpCount;
    }

private:
    uint64_t tcpCount = 0;
    uint64_t udpCount = 0;
    uint64_t icmpCount = 0;
};