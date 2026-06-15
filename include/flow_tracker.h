#pragma once

#include <string>
#include <unordered_map>
#include <cstdint>
#include <iostream>

struct FlowStats
{
    uint64_t packetCount = 0;
    uint64_t byteCount = 0;

    std::string domain;
    std::string application;

    uint16_t dstPort = 0;

    uint64_t firstSeen = 0;
    uint64_t lastSeen = 0;
};

class FlowTracker
{
public:
    void addPacket(
        const std::string& srcIP,
        const std::string& dstIP,
        uint16_t srcPort,
        uint16_t dstPort,
        size_t bytes,
        const std::string& domain = "",
        const std::string& application = ""
    );

    void printSummary() const;

    const std::unordered_map<
        std::string,
        FlowStats
    >& getFlows() const
    {
        return flows_;
    };

private:
    std::unordered_map<
        std::string,
        FlowStats
    > flows_;
};