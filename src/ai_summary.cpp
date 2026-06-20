#include "ai_summary.h"
#include "global_state.h"


#include <sstream>

std::string AISummary::generate()
{
    std::stringstream ss;

    uint64_t tcp = 0;
    uint64_t udp = 0;

    if (gProtocolStats)
    {
        tcp = gProtocolStats->getTCP();
        udp = gProtocolStats->getUDP();
    }

    size_t alerts = 0;

    if (gThreatDetector)
    {
        alerts =
            gThreatDetector
                ->getAlertCount();
    }

    ss << "Security Assessment: ";

    if (alerts == 0)
    {
        ss << "No active threats detected. ";
    }
    else
    {
        ss << alerts
           << " security alerts detected. ";
    }

    ss << "TCP="
       << tcp
       << " UDP="
       << udp
       << ". ";

    return ss.str();
}