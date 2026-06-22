#pragma once

#include <string>

struct Transaction
{
    std::string id;

    std::string sourceIP;

    std::string domain;

    std::string reason;

    std::string aiSummary;

    std::string status;
    int riskScore;
std::string recommendation;
};
