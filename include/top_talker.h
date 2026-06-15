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

private:
    std::unordered_map<
        std::string,
        uint64_t
    > ipBytes_;
};