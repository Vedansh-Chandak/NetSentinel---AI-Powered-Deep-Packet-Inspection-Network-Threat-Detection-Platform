#pragma once

#include <unordered_map>
#include <string>
#include <cstdint>

struct AppStats
{
    uint64_t packets = 0;
    uint64_t bytes = 0;
};

class AppTracker
{
public:
    void addTraffic(
        const std::string& app,
        size_t bytes
    );

    void printStats() const;

    const std::unordered_map<
        std::string,
        AppStats
    >& getApps() const
    {
        return apps_;
    }

private:
    std::unordered_map<
        std::string,
        AppStats
    > apps_;
};