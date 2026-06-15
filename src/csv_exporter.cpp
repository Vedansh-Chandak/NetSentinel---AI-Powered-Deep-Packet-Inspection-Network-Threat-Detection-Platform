#include "csv_exporter.h"

#include <fstream>
#include <iostream>

void CSVExporter::exportFlows(
    const std::unordered_map<
        std::string,
        FlowStats
    >& flows,
    const std::string& filename)
{
    std::cout
        << "\n[DEBUG] exportFlows called"
        << "\n[DEBUG] Flow count = "
        << flows.size()
        << std::endl;

    std::ofstream file(filename);

    if (!file.is_open())
    {
        std::cerr
            << "[ERROR] Failed to create "
            << filename
            << std::endl;
        return;
    }

    file
        << "Flow,"
        << "Packets,"
        << "Bytes,"
        << "Application,"
        << "Domain\n";

    for (const auto& [flowId, flow] : flows)
    {
        file
            << flowId << ","
            << flow.packetCount << ","
            << flow.byteCount << ","
            << flow.application << ","
            << flow.domain
            << "\n";
    }

    file.close();

    std::cout
        << "[CSV] Exported "
        << flows.size()
        << " flows to "
        << filename
        << std::endl;
}