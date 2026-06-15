#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>

class ThreatDetector
{
public:
    void analyzePacket(
        const std::string& srcIP,
        const std::string& dstIP,
        uint16_t dstPort
    );

    void printAlerts() const;

private:
    std::unordered_map<
        std::string,
        std::unordered_set<uint16_t>
    > scannedPorts_;
};