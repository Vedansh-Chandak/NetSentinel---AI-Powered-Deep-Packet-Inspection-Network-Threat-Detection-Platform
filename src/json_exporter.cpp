#include "json_exporter.h"

#include <fstream>
#include <iostream>

void JSONExporter::exportFlows(
    const std::unordered_map<
        std::string,
        FlowStats
    >& flows,
    const std::string& filename)
{
    std::ofstream file(filename);

    if (!file.is_open())
    {
        std::cerr
            << "Failed to create "
            << filename
            << std::endl;

        return;
    }

    file << "[\n";

    bool first = true;

    for (const auto& [flowId, flow] : flows)
    {
        if (!first)
        {
            file << ",\n";
        }

        first = false;

        file
            << "  {\n"
            << "    \"flow\": \"" << flowId << "\",\n"
            << "    \"packets\": " << flow.packetCount << ",\n"
            << "    \"bytes\": " << flow.byteCount << ",\n"
            << "    \"application\": \"" << flow.application << "\",\n"
            << "    \"domain\": \"" << flow.domain << "\"\n"
            << "  }";
    }

    file << "\n]\n";

    file.close();

    std::cout
        << "[JSON] Exported "
        << flows.size()
        << " flows to "
        << filename
        << std::endl;
}