#include "top_talker.h"

#include <iostream>
#include <vector>
#include <algorithm>

void TopTalker::addTraffic(
    const std::string& ip,
    size_t bytes)
{
    // Ignore invalid/empty IPs
    if (ip.empty())
    {
        return;
    }

    ipBytes_[ip] += bytes;
}

void TopTalker::printTop() const
{
    std::vector<
        std::pair<std::string, uint64_t>
    > ips(
        ipBytes_.begin(),
        ipBytes_.end()
    );

    std::sort(
        ips.begin(),
        ips.end(),
        [](const auto& a, const auto& b)
        {
            return a.second > b.second;
        }
    );

    std::cout
        << "\n=====================================\n"
        << "TOP TALKERS\n"
        << "=====================================\n";

    int count = 0;

    for (const auto& [ip, bytes] : ips)
    {
        // Extra safety check
        if (ip.empty())
        {
            continue;
        }

        std::cout
            << ip
            << " : "
            << bytes
            << " bytes\n";

        if (++count >= 5)
        {
            break;
        }
    }
}