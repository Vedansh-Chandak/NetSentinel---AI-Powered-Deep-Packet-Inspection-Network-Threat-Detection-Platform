#include "protocol_stats.h"

#include <iostream>

void ProtocolStats::addTCP()
{
    tcpCount++;
}

void ProtocolStats::addUDP()
{
    udpCount++;
}

void ProtocolStats::addICMP()
{
    icmpCount++;
}

void ProtocolStats::printStats() const
{
    uint64_t total =
        tcpCount +
        udpCount +
        icmpCount;

    if (total == 0)
        return;

    std::cout
        << "\n=====================================\n"
        << "PROTOCOL STATISTICS\n"
        << "=====================================\n";

    std::cout
        << "TCP  : "
        << tcpCount
        << "\n";

    std::cout
        << "UDP  : "
        << udpCount
        << "\n";

    std::cout
        << "ICMP : "
        << icmpCount
        << "\n";

    std::cout
        << "TOTAL: "
        << total
        << "\n";
}