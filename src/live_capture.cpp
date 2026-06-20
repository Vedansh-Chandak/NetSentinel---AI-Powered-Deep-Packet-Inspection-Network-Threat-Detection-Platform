#include "live_capture.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include "sni_extractor.h"
#include "flow_tracker.h"

#include <iostream>
#include <pcap/pcap.h>
#include <string>
#include "app_tracker.h"
#include "top_talker.h"
#include "threat_detector.h"
#include "service_mapper.h"
#include "protocol_stats.h"
#include "csv_exporter.h"
#include "json_exporter.h"
#include "api_server.h"
#include "global_state.h"


using namespace PacketAnalyzer;

// =====================================================
// Application Classifier
// =====================================================

std::string classifyDomain(const std::string& domain)
{
    if (domain.find("youtube") != std::string::npos)
        return "YouTube";

    if (domain.find("github") != std::string::npos)
        return "GitHub";

    if (domain.find("openai") != std::string::npos)
        return "OpenAI";

    if (domain.find("visualstudio") != std::string::npos)
        return "VS Code";

    if (domain.find("microsoft") != std::string::npos)
        return "Microsoft";

    if (domain.find("telegram") != std::string::npos)
        return "Telegram";

    if (domain.find("discord") != std::string::npos)
        return "Discord";

    if (domain.find("facebook") != std::string::npos)
        return "Facebook";

    if (domain.find("instagram") != std::string::npos)
        return "Instagram";

    if (domain.find("google") != std::string::npos)
        return "Google";

    return "Unknown";
}

bool LiveCapture::start(const char* interfaceName)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(
        interfaceName,
        BUFSIZ,
        1,
        1000,
        errbuf
    );

    if (!handle)
    {
        std::cerr
            << "Error opening interface: "
            << errbuf
            << std::endl;

        return false;
    }

    std::cout
        << "Listening on "
        << interfaceName
        << std::endl;

   FlowTracker tracker;
AppTracker appTracker;
TopTalker topTalker;
ThreatDetector threatDetector;

if (!threatDetector.loadRules("rules.txt"))
{
    std::cout
        << "Failed to load rules.txt\n";

    threatDetector.loadDefaultRules();
}

if (!threatDetector.loadDomainRules(
        "domains.txt"))
{
    std::cout
        << "Failed to load domains.txt\n";
}

if (!threatDetector.loadIPRules(
        "bad_ips.txt"))
{
    std::cout
        << "Failed to load bad_ips.txt\n";
}

ProtocolStats protocolStats;

gFlowTracker = &tracker;
gAppTracker = &appTracker;
gTopTalker = &topTalker;
gProtocolStats = &protocolStats;
gThreatDetector = &threatDetector;

std::cout << "\n===== GLOBAL STATE =====\n";

std::cout << "FlowTracker     : " << gFlowTracker << '\n';
std::cout << "AppTracker      : " << gAppTracker << '\n';
std::cout << "TopTalker       : " << gTopTalker << '\n';
std::cout << "ProtocolStats   : " << gProtocolStats << '\n';
std::cout << "ThreatDetector  : " << gThreatDetector << '\n';

APIServer::start();
uint64_t packetCounter = 0;

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true)
    {
        int result = pcap_next_ex(
            handle,
            &header,
            &packet
        );

        if (result != 1)
        {
            continue;
        }

        RawPacket raw;

        raw.header.ts_sec   = header->ts.tv_sec;
        raw.header.ts_usec  = header->ts.tv_usec;
        raw.header.incl_len = header->caplen;
        raw.header.orig_len = header->len;

        raw.data.assign(
            packet,
            packet + header->caplen
        );

     ParsedPacket parsed;

     if (!PacketParser::parse(raw, parsed))
{
    continue;
}

std::string service =
    ServiceMapper::getService(
        parsed.dest_port
    );

// Protocol Statistics
if (parsed.has_tcp)
    protocolStats.addTCP();

if (parsed.has_udp)
    protocolStats.addUDP();

if (parsed.protocol == 1)
    protocolStats.addICMP();

// Threat Detection
if (parsed.has_tcp || parsed.has_udp)
{
    threatDetector.analyzePacket(
        parsed.src_ip,
        parsed.dest_ip,
        parsed.dest_port
    );
    
    threatDetector.analyzeIP(
    parsed.src_ip
);

threatDetector.analyzeIP(
    parsed.dest_ip
);
}




// =====================================================
// Track every packet
// =====================================================

if (parsed.has_ip &&
    !parsed.src_ip.empty() &&
    !parsed.dest_ip.empty())
{
    // Top Talkers
    topTalker.addTraffic(
        parsed.src_ip,
        parsed.payload_length
    );

    topTalker.addTraffic(
        parsed.dest_ip,
        parsed.payload_length
    );

    // Flow Tracking
 tracker.addPacket(
    parsed.src_ip,
    parsed.dest_ip,
    parsed.src_port,
    parsed.dest_port,
    parsed.payload_length
);
}

        packetCounter++;
// =====================================================
// HTTPS TLS SNI Detection
// =====================================================

if (parsed.has_tcp &&
    parsed.dest_port == 443 &&
    parsed.payload_length > 0)
{
    auto domain =
        DPI::SNIExtractor::extract(
            parsed.payload_data,
            parsed.payload_length
        );
    

    if (domain)
{
    threatDetector.analyzeDomain(
        parsed.src_ip,
        *domain
    );

    std::string app =
        classifyDomain(*domain);

    appTracker.addTraffic(
        app,
        parsed.payload_length
    );

    tracker.addPacket(
        parsed.src_ip,
        parsed.dest_ip,
        parsed.src_port,
        parsed.dest_port,
        parsed.payload_length,
        *domain,
        app
    );

    std::cout
        << "\n[APP] "
        << app
        << "\n[DNS QUERY] "
        << *domain
        << std::endl;
   }

}
// =====================================================
// QUIC Detection
// =====================================================

if (parsed.has_udp &&
    parsed.dest_port == 443 &&
    parsed.payload_length > 0)
{
    auto domain =
        DPI::QUICSNIExtractor::extract(
            parsed.payload_data,
            parsed.payload_length
        );

    if (domain)
    {
        std::cout
            << "\n[QUIC DOMAIN] "
            << *domain
            << std::endl;
    }
}
     

        if (parsed.has_udp &&
            parsed.dest_port == 53 &&
            parsed.payload_length > 0)
        {
            auto domain =
                DPI::DNSExtractor::extractQuery(
                    parsed.payload_data,
                    parsed.payload_length
                );

        if (domain)
{

      threatDetector.analyzeDomain(
    parsed.src_ip,
    *domain
);
    std::string app =
        classifyDomain(*domain);

      

    appTracker.addTraffic(
        app,
        parsed.payload_length
    );

    tracker.addPacket(
        parsed.src_ip,
        parsed.dest_ip,
        parsed.src_port,
        parsed.dest_port,
        parsed.payload_length,
        *domain,
        app
    );

    std::cout
        << "\n[APP] "
        << app
        << "\n[DNS QUERY] "
        << *domain
        << std::endl;
}
        }
    

        // =====================================================
        // Packet Information
        // =====================================================

        if (parsed.has_ip)
        {
            std::cout
                << parsed.src_ip
                << " -> "
                << parsed.dest_ip
                << " | "
                << PacketParser::protocolToString(
                    parsed.protocol
                );

            if (parsed.has_tcp || parsed.has_udp)
            {
                std::cout
                    << " | "
                    << parsed.src_port
                    << " -> "
                    << parsed.dest_port;
            }

            std::cout
                << " | Payload: "
                << parsed.payload_length
                << std::endl;
        }

        // =====================================================
        // Flow Summary
        // =====================================================
if (packetCounter % 20 == 0)
{
   protocolStats.printStats();
    tracker.printSummary();
    appTracker.printStats();
    topTalker.printTop();
    threatDetector.printAlerts();
     
    std::cout
    << "\n[DEBUG] About to export CSV"
    << std::endl;

CSVExporter::exportFlows(
    tracker.getFlows(),
    "flows.csv"
);

JSONExporter::exportFlows(
    tracker.getFlows(),
    "flows.json"
);
}
    }

    pcap_close(handle);
    return true;
}


