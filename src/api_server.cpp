#include "api_server.h"
#include "global_state.h"

#include <iostream>
#include <thread>
#include <cstring>
#include <string>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

void APIServer::start()
{
    std::thread([]()
    {
        int server_fd = socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

        if (server_fd < 0)
        {
            std::cerr
                << "Socket creation failed\n";
            return;
        }

        int opt = 1;

        setsockopt(
            server_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &opt,
            sizeof(opt)
        );

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(8080);

        if (bind(
                server_fd,
                (sockaddr*)&address,
                sizeof(address)
            ) < 0)
        {
            std::cerr
                << "Bind failed\n";
            close(server_fd);
            return;
        }

        if (listen(server_fd, 10) < 0)
        {
            std::cerr
                << "Listen failed\n";
            close(server_fd);
            return;
        }

        std::cout
            << "\n=====================================\n"
            << "REST API SERVER\n"
            << "=====================================\n"
            << "Listening on port 8080\n";

        while (true)
        {
            int client =
                accept(
                    server_fd,
                    nullptr,
                    nullptr
                );

            if (client < 0)
                continue;

            char buffer[4096] = {0};

            recv(
                client,
                buffer,
                sizeof(buffer),
                0
            );

            std::string request(buffer);

            std::string body;

            // =====================================
            // GET /
            // =====================================

            if (request.find("GET / ") != std::string::npos)
            {
                size_t flowCount = 0;

                if (gFlowTracker)
                {
                    flowCount =
                        gFlowTracker
                            ->getFlows()
                            .size();
                }

                body =
                    "{"
                    "\"status\":\"running\","
                    "\"flows\":" +
                    std::to_string(flowCount) +
                    "}";
            }

            // =====================================
            // GET /stats
            // =====================================

            else if (
                request.find("GET /stats")
                != std::string::npos)
            {
                uint64_t tcp = 0;
                uint64_t udp = 0;
                uint64_t icmp = 0;

                if (gProtocolStats)
                {
                    tcp =
                        gProtocolStats->getTCP();

                    udp =
                        gProtocolStats->getUDP();

                    icmp =
                        gProtocolStats->getICMP();
                }

                body =
                    "{"
                    "\"tcp\":" +
                    std::to_string(tcp) +
                    ","
                    "\"udp\":" +
                    std::to_string(udp) +
                    ","
                    "\"icmp\":" +
                    std::to_string(icmp) +
                    "}";
            }

            // =====================================
            // GET /flows
            // =====================================

            else if (
                request.find("GET /flows")
                != std::string::npos)
            {
                body = "[";

                bool first = true;

                if (gFlowTracker)
                {
                    for (const auto& [id, flow]
                         : gFlowTracker->getFlows())
                    {
                        if (!first)
                            body += ",";

                        first = false;

                        body += "{";

                        body +=
                            "\"flow\":\"" +
                            id +
                            "\",";

                        body +=
                            "\"packets\":" +
                            std::to_string(
                                flow.packetCount
                            ) +
                            ",";

                        body +=
                            "\"bytes\":" +
                            std::to_string(
                                flow.byteCount
                            ) +
                            ",";

                        body +=
                            "\"application\":\"" +
                            flow.application +
                            "\",";

                        body +=
                            "\"domain\":\"" +
                            flow.domain +
                            "\"";

                        body += "}";
                    }
                }

                body += "]";
            }


         // =====================================
// GET /top-talkers
// =====================================

else if (
    request.find("GET /top-talkers")
    != std::string::npos)
{
    body = "[";

    bool first = true;

    if (gTopTalker)
    {
        for (const auto& [ip, bytes]
             : gTopTalker->getTalkers())
        {
            if (!first)
                body += ",";

            first = false;

            body += "{";

            body +=
                "\"ip\":\"" +
                ip +
                "\",";

            body +=
                "\"bytes\":" +
                std::to_string(bytes);

            body += "}";

        }
    }

    body += "]";
}


else if (
    request.find("GET /ai-summary")
    != std::string::npos)
{
    std::string summary;

    // Protocol info
    uint64_t tcp = 0;
    uint64_t udp = 0;

    if (gProtocolStats)
    {
        tcp = gProtocolStats->getTCP();
        udp = gProtocolStats->getUDP();
    }

    summary += "Network activity observed. ";

    if (tcp > udp)
    {
        summary +=
            "TCP traffic dominates. ";
    }
    else
    {
        summary +=
            "UDP traffic dominates. ";
    }

    // Threat info
    if (gThreatDetector)
    {
        size_t alerts =
            gThreatDetector
                ->getAlertCount();

        if (alerts > 0)
        {
            summary +=
                std::to_string(alerts) +
                " security alerts detected. ";
        }
        else
        {
            summary +=
                "No security alerts detected. ";
        }
    }

    // Threat score
    int score = 0;

    if (gThreatDetector)
    {
        score =
            gThreatDetector
                ->getThreatScore();
    }

    summary +=
        "Threat score is " +
        std::to_string(score) +
        ".";

    body =
        "{"
        "\"summary\":\"" +
        summary +
        "\""
        "}";
}



else if (
    request.find("GET /applications")
    != std::string::npos)
{
    body = "[";

    bool first = true;

    if (gAppTracker)
    {
        for (const auto& [app, stats]
             : gAppTracker->getApps())
        {
            if (!first)
                body += ",";

            first = false;

            body += "{";

            body +=
                "\"app\":\"" +
                app +
                "\",";

            body +=
                "\"packets\":" +
                std::to_string(
                    stats.packets
                ) +
                ",";

            body +=
                "\"bytes\":" +
                std::to_string(
                    stats.bytes
                );

            body += "}";
        }
    }

    body += "]";
}


else if (
    request.find("GET /threat-score")
    != std::string::npos)
{
    int score = 0;

    if (gThreatDetector)
    {
        score =
            gThreatDetector
                ->getThreatScore();
    }

    std::string level;

    if (score >= 70)
    {
        level = "HIGH";
    }
    else if (score >= 30)
    {
        level = "MEDIUM";
    }
    else
    {
        level = "LOW";
    }

    body =
        "{"
        "\"score\":" +
        std::to_string(score) +
        ","
        "\"level\":\"" +
        level +
        "\""
        "}";
}

else if (
    request.find("GET /alerts")
    != std::string::npos)
{
    body = "[";

    bool first = true;

    if (gThreatDetector)
    {
        for (const auto& alert :
             gThreatDetector->getAlerts())
        {
            if (!first)
                body += ",";

            first = false;

            body += "{";

            body +=
                "\"severity\":\"" +
                alert.severity +
                "\",";

            body +=
                "\"type\":\"" +
                alert.type +
                "\",";

            body +=
                "\"source\":\"" +
                alert.sourceIP +
                "\",";

            body +=
                "\"details\":\"" +
                alert.details +
                "\"";

            body += "}";
        }
    }

    body += "]";
}

// =====================================
// GET /rules
// =====================================

else if (
    request.find("GET /rules")
    != std::string::npos)
{
    body = "[";

    bool first = true;

    if (gThreatDetector)
    {
        for (const auto& rule :
             gThreatDetector->getRules())
        {
            if (!first)
                body += ",";

            first = false;

            body += "{";

            body +=
                "\"name\":\"" +
                rule.name +
                "\",";

            body +=
                "\"port\":" +
                std::to_string(
                    rule.port
                ) +
                ",";

            body +=
                "\"severity\":\"" +
                rule.severity +
                "\"";

            body += "}";
        }
    }

    body += "]";
}

//dashboard

else if (
    request.find("GET /dashboard")
    != std::string::npos)
{
    body =
R"(
<html>
<head>
<title>Packet Analyzer Dashboard</title>
</head>

<body>

<h1>Packet Analyzer Dashboard</h1>

<h2>Protocol Statistics</h2>
<table border="1">
    <tbody id="stats"></tbody>
</table>

<h2>Top Talkers</h2>
<table border="1">
    <thead>
        <tr>
            <th>IP Address</th>
            <th>Bytes</th>
        </tr>
    </thead>
    <tbody id="talkers"></tbody>
</table>

<h2>Applications</h2>
<table border="1">
    <thead>
        <tr>
            <th>Application</th>
            <th>Packets</th>
            <th>Bytes</th>
        </tr>
    </thead>
    <tbody id="apps"></tbody>
</table>



<h2>Security Alerts</h2>

<table border="1">
    <thead>
        <tr>
            <th>Type</th>
            <th>Source</th>
            <th>Details</th>
        </tr>
    </thead>

    <tbody id="alerts"></tbody>
</table>

<h2>AI Summary</h2>

<pre id="summary">
Loading...
</pre>

<h2>Threat Score</h2>

<pre id="threatScore">
Loading...
</pre>

<script>

async function refresh()
{
    // ==========================
    // Protocol Stats
    // ==========================

    let statsResponse =
        await fetch('/stats');

    let stats =
        await statsResponse.json();

    document.getElementById(
        'stats'
    ).innerHTML =
        `
        <tr>
            <td>TCP</td>
            <td>${stats.tcp}</td>
        </tr>
        <tr>
            <td>UDP</td>
            <td>${stats.udp}</td>
        </tr>
        <tr>
            <td>ICMP</td>
            <td>${stats.icmp}</td>
        </tr>
        `;

    // ==========================
    // Top Talkers
    // ==========================

    let talkersResponse =
        await fetch('/top-talkers');

    let talkers =
        await talkersResponse.json();

    let talkerRows = "";

    for (const t of talkers)
    {
        talkerRows +=
        `
        <tr>
            <td>${t.ip}</td>
            <td>${t.bytes}</td>
        </tr>
        `;
    }

    document.getElementById(
        'talkers'
    ).innerHTML =
        talkerRows;




        // ==========================
// Security Alerts
// ==========================

let alertsResponse =
    await fetch('/alerts');

let alerts =
    await alertsResponse.json();

let alertRows = "";

for (const a of alerts)
{
    alertRows +=
    `
    <tr>
        <td>${a.severity}</td>
    <td>${a.type}</td>
    <td>${a.source}</td>
    <td>${a.details}</td>
    </tr>
    `;
}

document.getElementById(
    'alerts'
).innerHTML =
    alertRows;

    let threat =
    await fetch('/threat-score');

document.getElementById(
    'threatScore'
).innerText =
    await threat.text();
//summery
    let summary =
    await fetch('/ai-summary');

document.getElementById(
    'summary'
).innerText =
    await summary.text();
        
    // ==========================
    // Applications
    // ==========================

    let appsResponse =
        await fetch('/applications');

    let apps =
        await appsResponse.json();

    let appRows = "";

    for (const a of apps)
    {
        appRows +=
        `
        <tr>
            <td>${a.app}</td>
            <td>${a.packets}</td>
            <td>${a.bytes}</td>
        </tr>
        `;
    }

    document.getElementById(
        'apps'
    ).innerHTML =
        appRows;
}

refresh();

setInterval(
    refresh,
    3000
);

</script>

</body>
</html>
)";
    std::string response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: " +
        std::to_string(body.size()) +
        "\r\n\r\n" +
        body;

    send(
        client,
        response.c_str(),
        response.size(),
        0
    );

    close(client);
    continue;
}


            // =====================================
            // Unknown endpoint
            // =====================================

            else
            {
                body =
                    "{\"error\":\"not found\"}";
            }

            std::string response =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: " +
                std::to_string(body.size()) +
                "\r\n\r\n" +
                body;

            send(
                client,
                response.c_str(),
                response.size(),
                0
            );

            close(client);
        }

    }).detach();
}