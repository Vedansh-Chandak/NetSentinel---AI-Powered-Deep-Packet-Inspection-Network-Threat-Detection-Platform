#include "app_tracker.h"

#include <iostream>

void AppTracker::addTraffic(
    const std::string& app,
    size_t bytes)
{
    auto& stats = apps_[app];

    stats.packets++;
    stats.bytes += bytes;
}

void AppTracker::printStats() const
{
    std::cout
        << "\n=====================================\n"
        << "APPLICATION STATISTICS\n"
        << "=====================================\n";

    for (const auto& [app, stats] : apps_)
    {
        std::cout
            << app
            << "\n";

        std::cout
            << "  Packets : "
            << stats.packets
            << "\n";

        std::cout
            << "  Bytes   : "
            << stats.bytes
            << "\n\n";
    }
}