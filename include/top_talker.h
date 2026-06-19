#pragma once

#include <string>
#include <unordered_map>
#include <cstdint>

class TopTalker
{
public:
    void addTraffic(
        const std::string& ip,
        size_t bytes
    );

    void printTop() const;

    const std::unordered_map<
        std::string,
        uint64_t
    >& getTalkers() const
    {
        return ipBytes_;
    }

private:
    std::unordered_map<
        std::string,
        uint64_t
    > ipBytes_;
};