#include "flow_tracker.h"
#include "service_mapper.h"

#include <ctime>
#include <iostream>

void FlowTracker::addPacket(
    const std::string& srcIP,
    const std::string& dstIP,
    uint16_t srcPort,
    uint16_t dstPort,
    size_t bytes,
    const std::string& domain,
    const std::string& application)
{
    std::string key =
        srcIP + ":" +
        std::to_string(srcPort) +
        " -> " +
        dstIP + ":" +
        std::to_string(dstPort);

    auto& flow = flows_[key];

    // Store destination port
    flow.dstPort = dstPort;

    flow.packetCount++;
    flow.byteCount += bytes;

    if (!domain.empty())
        flow.domain = domain;

    if (!application.empty())
        flow.application = application;

    uint64_t now =
        static_cast<uint64_t>(time(nullptr));

    if (flow.firstSeen == 0)
        flow.firstSeen = now;

    flow.lastSeen = now;
}

void FlowTracker::printSummary() const
{
    std::cout
        << "\n=====================================\n"
        << "FLOW SUMMARY\n"
        << "=====================================\n";

    for (const auto& [key, flow] : flows_)
    {
        std::cout
            << key
            << "\n";

        std::cout
            << "Service     : "
            << ServiceMapper::getService(
                   flow.dstPort
               )
            << "\n";

        if (!flow.application.empty())
        {
            std::cout
                << "Application : "
                << flow.application
                << "\n";
        }

        if (!flow.domain.empty())
        {
            std::cout
                << "Domain      : "
                << flow.domain
                << "\n";
        }

        std::cout
            << "Packets     : "
            << flow.packetCount
            << "\n";

        std::cout
            << "Bytes       : "
            << flow.byteCount
            << "\n";

        std::cout
            << "Duration    : "
            << (flow.lastSeen - flow.firstSeen)
            << " sec\n";

        std::cout << "\n";
    }
}