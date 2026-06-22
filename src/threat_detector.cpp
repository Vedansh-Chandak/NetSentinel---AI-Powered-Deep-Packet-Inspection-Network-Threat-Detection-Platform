#include "threat_detector.h"
#include "transaction_manager.h"
#include "global_state.h"

#include <iostream>
#include <cctype>
#include <ctime>
namespace
{
    bool looksSuspiciousDomain(
        const std::string& domain
    )
    {
        if (domain.size() > 40)
        {
            return true;
        }

        int digits = 0;

        for (char c : domain)
        {
            if (std::isdigit(
                static_cast<unsigned char>(c)))
            {
                digits++;
            }
        }

        return digits >= 8;
    }
}


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

    // Ignore multicast traffic
    if (dstIP.rfind("224.", 0) == 0)
    {
        return;
    }

    scannedPorts_[srcIP].insert(
        dstPort
    );

    // =====================================
    // Suspicious Port Detection
    // =====================================
for (const auto& rule : rules_)
{
    if (dstPort == rule.port)
    {
        alerts_.push_back(
        {
            rule.severity,
            rule.name,
            srcIP,
            "Connected to port " +
            std::to_string(dstPort)
        });
    }
}

    // =====================================
    // Port Scan Detection
    // =====================================

    if (
    scannedPorts_[srcIP].size() >= 10 &&
    alertedScanners_.count(srcIP) == 0
)
{
    alerts_.push_back(
    {
        "HIGH",
        "Port Scan",
        srcIP,
        "Touched " +
        std::to_string(
            scannedPorts_[srcIP].size()
        ) +
        " ports"
    });

    alertedScanners_.insert(
        srcIP
    );
}
}

void ThreatDetector::printAlerts() const
{
    std::cout
        << "\n=====================================\n"
        << "SECURITY ALERTS\n"
        << "=====================================\n";

    if (alerts_.empty())
    {
        std::cout
            << "No threats detected.\n";
        return;
    }

    for (const auto& alert : alerts_)
    {
        std::cout
         << "[" << alert.severity << "] "
            << "[" << alert.type << "] "
            << alert.sourceIP
            << " - "
            << alert.details
            << "\n";
    }
}
int ThreatDetector::getThreatScore() const
{
    int score = 0;

    for (const auto& alert : alerts_)
    {
        if (alert.type == "Port Scan")
        {
            score += 40;
        }
        else if (
            alert.type ==
            "Suspicious Port")
        {
            score += 20;
        }
    }

    if (score > 100)
    {
        score = 100;
    }

    return score;
}

void ThreatDetector::loadDefaultRules()
{
    rules_.push_back(
    {
        "TELNET",
        23,
        "HIGH"
    });

    rules_.push_back(
    {
        "FTP",
        21,
        "MEDIUM"
    });

    rules_.push_back(
    {
        "SMB",
        445,
        "HIGH"
    });

    rules_.push_back(
    {
        "RDP",
        3389,
        "HIGH"
    });

    rules_.push_back(
    {
        "MYSQL",
        3306,
        "LOW"
    });
}
bool ThreatDetector::loadRules(
    const std::string& filename)
{
    std::ifstream file(filename);

    if (!file.is_open())
    {
        return false;
    }

    rules_.clear();

    std::string line;

    while (std::getline(file, line))
    {
        if (line.empty())
            continue;

        std::stringstream ss(line);

        std::string name;
        std::string portStr;
        std::string severity;

        std::getline(ss, name, ',');
        std::getline(ss, portStr, ',');
        std::getline(ss, severity);

        Rule rule;

        rule.name = name;
        rule.port =
            static_cast<uint16_t>(
                std::stoi(portStr)
            );
        rule.severity = severity;

        rules_.push_back(rule);
    }

    std::cout
        << "Loaded "
        << rules_.size()
        << " IDS rules\n";

    return true;
}

void ThreatDetector::analyzeDomain(
    const std::string& srcIP,
    const std::string& domain
)
{
    std::cout
    << "\n[DOMAIN CHECK] "
    << domain
    << " RulesLoaded="
    << domainRules_.size()
    << std::endl;

for (const auto& rule :
     domainRules_)
{
    
    if (
        domain.find(
            rule.domain
        ) != std::string::npos
    )
    {
        if (alertedDomains_.count(domain))
{
    return;
}

alertedDomains_.insert(domain);

Transaction tx;

tx.id =
    "TX-" +
    std::to_string(
        std::time(nullptr)
    );

tx.sourceIP =
    srcIP;

tx.domain =
    domain;

tx.reason =
    "Blocked Domain";

tx.riskScore = 85;

tx.recommendation =
    "BLOCK";

tx.aiSummary =
    "The requested domain matched a blocked-domain policy. "
    "Risk level is HIGH and communication should be blocked.";

tx.status =
    "PENDING";

if (gTransactionManager)
{
    gTransactionManager
        ->addTransaction(tx);
}

alerts_.push_back(
{
    rule.severity,
    "Blocked Domain",
    srcIP,
    domain
});

        return;
    }
}

    static std::unordered_set<
        std::string
    > badDomains =
    {
        "malware.test",
        "evil.test",
        "phishing.test"
    };

    if (
        badDomains.count(domain)
    )
    {
        alerts_.push_back(
        {
            "HIGH",
            "Malicious Domain",
            srcIP,
            domain
        });

        return;
    }

  if (
    looksSuspiciousDomain(
        domain
    )
)
{
    if (alertedDomains_.count(domain))
    {
        return;
    }

    alertedDomains_.insert(domain);

    alerts_.push_back(
    {
        "MEDIUM",
        "Suspicious Domain",
        srcIP,
        domain
    });
}
}

void ThreatDetector::analyzeIP(
    const std::string& srcIP)
{
    for (const auto& rule :
         ipRules_)
    {
        if (srcIP == rule.ip)
        {
            // Already alerted
            if (alertedIPs_.count(srcIP))
            {
                return;
            }

            alertedIPs_.insert(srcIP);

 Transaction tx;

tx.id =
    "TX-" +
    std::to_string(
        std::time(nullptr)
    );

tx.sourceIP =
    srcIP;

tx.domain =
    srcIP;

tx.reason =
    "Malicious IP";

tx.riskScore = 95;

tx.recommendation =
    "BLOCK";

tx.aiSummary =
    "Traffic matches a known malicious IP address. "
    "Connection presents a critical security risk.";
tx.status =
    "PENDING";

if (gTransactionManager)
{
    gTransactionManager
        ->addTransaction(tx);
}

          alerts_.push_back(
{
    rule.severity,
    "Malicious IP",
    srcIP,
    "Matched threat intelligence feed"
});
            return;
        }
    }
}

bool ThreatDetector::loadDomainRules(
    const std::string& filename)
{
    std::ifstream file(filename);

    if (!file.is_open())
    {
        return false;
    }

    domainRules_.clear();

    std::string line;

    while (std::getline(file, line))
    {
        if (line.empty())
            continue;

        std::stringstream ss(line);

        std::string domain;
        std::string severity;

        std::getline(ss, domain, ',');
        std::getline(ss, severity);

        DomainRule rule;

        rule.domain = domain;
        rule.severity = severity;

        domainRules_.push_back(rule);
    }

    std::cout
        << "Loaded "
        << domainRules_.size()
        << " Domain Rules\n";

    return true;
}

bool ThreatDetector::loadIPRules(
    const std::string& filename)
{
    std::ifstream file(filename);

    if (!file.is_open())
    {
        return false;
    }

    ipRules_.clear();

    std::string line;

    while (std::getline(file, line))
    {
        if (line.empty())
            continue;

        std::stringstream ss(line);

        std::string ip;
        std::string severity;

        std::getline(ss, ip, ',');
        std::getline(ss, severity);

        IPRule rule;

        rule.ip = ip;
        rule.severity = severity;

        ipRules_.push_back(rule);
    }

    std::cout
        << "Loaded "
        << ipRules_.size()
        << " IP Rules\n";

    return true;
}