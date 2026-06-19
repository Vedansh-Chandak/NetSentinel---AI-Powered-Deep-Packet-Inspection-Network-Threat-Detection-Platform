#pragma once

#include <string>
#include <unordered_map>

#include "flow_tracker.h"

class JSONExporter
{
public:
    static void exportFlows(
        const std::unordered_map<
            std::string,
            FlowStats
        >& flows,
        const std::string& filename
    );
};