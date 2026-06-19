#pragma once
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <unordered_map>
#include <unordered_set>
#include "rule.h"
#include "domain_rule.h"

struct SecurityAlert
{
    std::string severity;
    std::string type;
    std::string sourceIP;
    std::string details;
};

class ThreatDetector
{
public:
    void analyzePacket(
        const std::string& srcIP,
        const std::string& dstIP,
        uint16_t dstPort
    );

    void printAlerts() const;

    int getThreatScore() const;

     bool loadRules(
    const std::string& filename
);



    void loadDefaultRules();
    bool loadDomainRules(
    const std::string& filename
);

void analyzeDomain(
    const std::string& srcIP,
    const std::string& domain
);

  

   

    const std::vector<Rule>& getRules() const
    {
        return rules_;
    }

   

    const std::vector<
        SecurityAlert
    >& getAlerts() const
    {
        return alerts_;
    }

    size_t getAlertCount() const
    {
        return alerts_.size();
    }

private:
    std::unordered_map<
        std::string,
        std::unordered_set<uint16_t>
    > scannedPorts_;

    std::unordered_set<
        std::string
    > alertedScanners_;

    std::vector<Rule> rules_;
     std::vector<DomainRule>
domainRules_;

    std::vector<
        SecurityAlert
    > alerts_;

};