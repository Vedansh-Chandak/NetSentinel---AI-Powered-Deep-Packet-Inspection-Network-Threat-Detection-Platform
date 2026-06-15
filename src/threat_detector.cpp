#include "threat_detector.h"

#include <iostream>

void ThreatDetector::analyzePacket(
    const std::string& srcIP,
    const std::string& dstIP,
    uint16_t dstPort)
{
    if (srcIP.empty())
        return;

    // Ignore DNS servers
    if (srcIP == "8.8.8.8" ||
        srcIP == "8.8.4.4")
    {
        return;
    }

    // Ignore multicast/broadcast
    if (dstIP.rfind("224.", 0) == 0)
    {
        return;
    }

    scannedPorts_[srcIP].insert(dstPort);
}

void ThreatDetector::printAlerts() const
{
    std::cout
        << "\n=====================================\n"
        << "SECURITY ALERTS\n"
        << "=====================================\n";

    bool found = false;

    for (const auto& [ip, ports] : scannedPorts_)
    {
        if (ports.size() >= 10)
        {
            found = true;

            std::cout
                << "[PORT SCAN] "
                << ip
                << " touched "
                << ports.size()
                << " ports\n";
        }
    }

    if (!found)
    {
        std::cout
            << "No threats detected.\n";
    }
}