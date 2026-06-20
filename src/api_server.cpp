#include "api_server.h"
#include "global_state.h"

#include <iostream>
#include <thread>
#include <cstring>
#include <string>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdlib>

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

    uint64_t tcp = 0;
    uint64_t udp = 0;

    if (gProtocolStats)
    {
        tcp = gProtocolStats->getTCP();
        udp = gProtocolStats->getUDP();
    }

    if (tcp > udp)
    {
        summary +=
            "Network traffic is primarily TCP-based. ";
    }
    else
    {
        summary +=
            "Network traffic is primarily UDP-based. ";
    }

    if (gAppTracker)
    {
        summary +=
            std::to_string(
                gAppTracker->getApps().size()
            ) +
            " unique applications were detected. ";
    }

    if (gThreatDetector)
    {
        size_t alerts =
            gThreatDetector->getAlertCount();

        int score =
            gThreatDetector->getThreatScore();

        std::string risk =
            score >= 70 ? "HIGH" :
            score >= 40 ? "MEDIUM" :
                          "LOW";

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

        summary +=
            "Threat score remains at " +
            risk +
            " risk (" +
            std::to_string(score) +
            "/100). ";

        bool portScanFound = false;

        for (const auto& alert :
             gThreatDetector->getAlerts())
        {
            if (alert.type == "Port Scan")
            {
                portScanFound = true;
                break;
            }
        }

        if (portScanFound)
        {
            summary +=
                "Potential port scanning activity was detected.";
        }
        else
        {
            summary +=
                "No port scanning activity detected.";
        }
    }

    body =
        "{"
        "\"summary\":\"" +
        summary +
        "\""
        "}";
}
   // Threat score


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
R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Packet Analyzer Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
  .scrollbar-thin::-webkit-scrollbar { width: 6px; height: 6px; }
  .scrollbar-thin::-webkit-scrollbar-thumb { background: #2a2d3a; border-radius: 8px; }
  .view { display: none; }
  .view.active { display: block; }
</style>
</head>
<body class="bg-[#0d0e14] text-slate-200 min-h-screen flex">

  <!-- Sidebar -->
  <aside class="w-60 shrink-0 bg-[#11131c] border-r border-white/5 flex flex-col px-5 py-6">
    <div class="flex items-center gap-2 mb-10 px-1">
      <div class="w-7 h-7 rounded-md bg-gradient-to-br from-violet-500 to-fuchsia-500"></div>
      <span class="font-semibold text-white text-[15px]">NetSentinel</span>
    </div>

    <nav id="sidebarNav" class="flex flex-col gap-1 text-sm">
      <button data-view="overview" class="nav-btn flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition">
        <span class="dot w-1.5 h-1.5 rounded-full"></span> Overview
      </button>
      <button data-view="flows" class="nav-btn flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition">
        <span class="dot w-1.5 h-1.5 rounded-full"></span> Flows
      </button>
      <button data-view="applications" class="nav-btn flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition">
        <span class="dot w-1.5 h-1.5 rounded-full"></span> Applications
      </button>
      <button data-view="alerts" class="nav-btn flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition">
        <span class="dot w-1.5 h-1.5 rounded-full"></span> Alerts
      </button>
      <button data-view="rules" class="nav-btn flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition">
        <span class="dot w-1.5 h-1.5 rounded-full"></span> Rules
      </button>
    </nav>

    <div class="mt-auto rounded-xl bg-white/[0.04] border border-white/5 p-4 text-xs text-slate-400">
      <p class="text-slate-300 font-medium mb-1">Live capture</p>
      <p>Port 8080 · auto-refresh 3s</p>
    </div>
  </aside>

  <!-- Main -->
  <main class="flex-1 px-8 py-7 max-w-[1400px]">

    <!-- Header -->
    <div class="flex items-center justify-between mb-7">
      <div>
        <h1 id="pageTitle" class="text-2xl font-semibold text-white">Network Overview</h1>
        <p id="pageSubtitle" class="text-sm text-slate-500 mt-1">Real-time packet inspection &amp; threat detection</p>
      </div>
      <div class="flex items-center gap-3">
        <span class="flex items-center gap-2 text-xs text-emerald-400 bg-emerald-400/10 px-3 py-1.5 rounded-full border border-emerald-400/20">
          <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> Live
        </span>
      </div>
    </div>

    <!-- ============ VIEW: OVERVIEW ============ -->
    <section id="view-overview" class="view active">

      <div class="grid grid-cols-4 gap-4 mb-6">
        <div class="bg-[#13151f] border border-white/5 rounded-2xl p-5">
          <p class="text-xs text-slate-500 mb-2">TCP Packets</p>
          <p id="statTcp" class="text-3xl font-semibold text-white">—</p>
          <p class="text-xs text-sky-400 mt-2">Transport layer</p>
        </div>
        <div class="bg-[#13151f] border border-white/5 rounded-2xl p-5">
          <p class="text-xs text-slate-500 mb-2">UDP Packets</p>
          <p id="statUdp" class="text-3xl font-semibold text-white">—</p>
          <p class="text-xs text-violet-400 mt-2">Transport layer</p>
        </div>
        <div class="bg-[#13151f] border border-white/5 rounded-2xl p-5">
          <p class="text-xs text-slate-500 mb-2">ICMP Packets</p>
          <p id="statIcmp" class="text-3xl font-semibold text-white">—</p>
          <p class="text-xs text-amber-400 mt-2">Control messages</p>
        </div>
        <div class="bg-[#13151f] border border-white/5 rounded-2xl p-5">
          <p class="text-xs text-slate-500 mb-2">Threat score</p>
          <div class="flex items-baseline gap-2">
            <p id="threatScoreVal" class="text-3xl font-semibold text-white">—</p>
            <span id="threatLevelBadge" class="text-[11px] px-2 py-0.5 rounded-full font-medium"></span>
          </div>
          <p class="text-xs text-slate-500 mt-2">0–100 scale</p>
        </div>
      </div>

      <div class="grid grid-cols-3 gap-4 mb-6">
        <div class="col-span-2 bg-[#13151f] border border-white/5 rounded-2xl p-5">
          <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-medium text-white">AI Summary</h2>
            <span class="text-[10px] uppercase tracking-wide text-slate-500">auto-generated</span>
          </div>
          <p id="summaryText" class="text-sm text-slate-400 leading-relaxed">Loading...</p>
        </div>

        <div class="bg-[#13151f] border border-white/5 rounded-2xl p-5">
          <h2 class="text-sm font-medium text-white mb-4">Applications</h2>
          <div id="appsOverviewList" class="flex flex-col gap-3 max-h-40 overflow-y-auto scrollbar-thin"></div>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-4">
        <div class="bg-[#13151f] border border-white/5 rounded-2xl p-5">
          <h2 class="text-sm font-medium text-white mb-4">Top Talkers</h2>
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-xs text-slate-500 border-b border-white/5">
                <th class="pb-2 font-normal">IP Address</th>
                <th class="pb-2 font-normal text-right">Bytes</th>
              </tr>
            </thead>
            <tbody id="talkers" class="text-slate-300"></tbody>
          </table>
        </div>

        <div class="bg-[#13151f] border border-white/5 rounded-2xl p-5">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-sm font-medium text-white">Security Alerts</h2>
            <span id="alertCountOverview" class="text-[11px] px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 font-medium">0</span>
          </div>
          <div id="alertsOverviewList" class="flex flex-col gap-2 max-h-56 overflow-y-auto scrollbar-thin"></div>
        </div>
      </div>

    </section>

    <!-- ============ VIEW: FLOWS ============ -->
    <section id="view-flows" class="view">
      <div class="bg-[#13151f] border border-white/5 rounded-2xl p-5">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-sm font-medium text-white">Active Flows</h2>
          <span id="flowCount" class="text-[11px] px-2 py-0.5 rounded-full bg-sky-500/10 text-sky-400 font-medium">0</span>
        </div>
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-xs text-slate-500 border-b border-white/5">
              <th class="pb-2 font-normal">Flow</th>
              <th class="pb-2 font-normal">Application</th>
              <th class="pb-2 font-normal">Domain</th>
              <th class="pb-2 font-normal text-right">Packets</th>
              <th class="pb-2 font-normal text-right">Bytes</th>
            </tr>
          </thead>
          <tbody id="flowsTable" class="text-slate-300"></tbody>
        </table>
      </div>
    </section>

    <!-- ============ VIEW: APPLICATIONS ============ -->
    <section id="view-applications" class="view">
      <div class="bg-[#13151f] border border-white/5 rounded-2xl p-5">
        <h2 class="text-sm font-medium text-white mb-4">Traffic by Application</h2>
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-xs text-slate-500 border-b border-white/5">
              <th class="pb-2 font-normal">Application</th>
              <th class="pb-2 font-normal text-right">Packets</th>
              <th class="pb-2 font-normal text-right">Bytes</th>
            </tr>
          </thead>
          <tbody id="appsTable" class="text-slate-300"></tbody>
        </table>
      </div>
    </section>

    <!-- ============ VIEW: ALERTS ============ -->
    <section id="view-alerts" class="view">
      <div class="bg-[#13151f] border border-white/5 rounded-2xl p-5">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-sm font-medium text-white">All Security Alerts</h2>
          <span id="alertCountFull" class="text-[11px] px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 font-medium">0</span>
        </div>
        <div id="alertsFullList" class="flex flex-col gap-2"></div>
      </div>
    </section>

    <!-- ============ VIEW: RULES ============ -->
    <section id="view-rules" class="view">
      <div class="bg-[#13151f] border border-white/5 rounded-2xl p-5">
        <h2 class="text-sm font-medium text-white mb-4">Detection Rules</h2>
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-xs text-slate-500 border-b border-white/5">
              <th class="pb-2 font-normal">Rule Name</th>
              <th class="pb-2 font-normal">Port</th>
              <th class="pb-2 font-normal text-right">Severity</th>
            </tr>
          </thead>
          <tbody id="rulesTable" class="text-slate-300"></tbody>
        </table>
      </div>
    </section>

  </main>

<script>
const titles = {
  overview:     ["Network Overview",   "Real-time packet inspection & threat detection"],
  flows:        ["Active Flows",       "Every tracked connection by 5-tuple"],
  applications: ["Applications",       "Traffic broken down by classified app"],
  alerts:       ["Security Alerts",    "Every threat detected since capture started"],
  rules:        ["Detection Rules",    "Port and domain rules currently loaded"]
};

function setActiveView(view) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('view-' + view).classList.add('active');

  document.querySelectorAll('.nav-btn').forEach(btn => {
    const isActive = btn.dataset.view === view;
    btn.classList.toggle('bg-white/[0.06]', isActive);
    btn.classList.toggle('text-white', isActive);
    btn.classList.toggle('font-medium', isActive);
    btn.classList.toggle('text-slate-400', !isActive);
    btn.querySelector('.dot').classList.toggle('bg-violet-400', isActive);
    btn.querySelector('.dot').classList.toggle('bg-slate-600', !isActive);
  });

  document.getElementById('pageTitle').innerText = titles[view][0];
  document.getElementById('pageSubtitle').innerText = titles[view][1];

  localStorage.setItem('netsentinel_view', view);
}

document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => setActiveView(btn.dataset.view));
});

const sevColor = (sev) => {
  sev = (sev || "").toUpperCase();
  if (sev === "HIGH" || sev === "CRITICAL") return "bg-rose-500/10 text-rose-400 border-rose-500/20";
  if (sev === "MEDIUM") return "bg-amber-500/10 text-amber-400 border-amber-500/20";
  return "bg-sky-500/10 text-sky-400 border-sky-500/20";
};

const levelColor = (lvl) => {
  if (lvl === "HIGH") return "bg-rose-500/15 text-rose-400";
  if (lvl === "MEDIUM") return "bg-amber-500/15 text-amber-400";
  return "bg-emerald-500/15 text-emerald-400";
};

function alertRow(a) {
  return `
    <div class="flex items-start gap-3 px-3 py-2.5 rounded-lg border ${sevColor(a.severity)}">
      <span class="text-[10px] font-semibold uppercase tracking-wide mt-0.5">${a.severity}</span>
      <div class="flex-1 min-w-0">
        <p class="text-xs font-medium text-slate-200">${a.type}</p>
        <p class="text-xs text-slate-500 truncate">${a.source} — ${a.details}</p>
      </div>
    </div>
  `;
}

async function refresh() {
  // ---- Overview: protocol stats ----
  let stats = await (await fetch('/stats')).json();
  document.getElementById('statTcp').innerText = stats.tcp;
  document.getElementById('statUdp').innerText = stats.udp;
  document.getElementById('statIcmp').innerText = stats.icmp;

  // ---- Overview: top talkers ----
  let talkers = await (await fetch('/top-talkers')).json();
  document.getElementById('talkers').innerHTML = talkers.map(t => `
    <tr class="border-b border-white/[0.03] last:border-0">
      <td class="py-2 font-mono text-xs text-slate-300">${t.ip}</td>
      <td class="py-2 text-right text-slate-400">${t.bytes.toLocaleString()}</td>
    </tr>
  `).join('');

  // ---- Alerts (shared by Overview + Alerts tab) ----
  let alerts = await (await fetch('/alerts')).json();
  document.getElementById('alertCountOverview').innerText = alerts.length;
  document.getElementById('alertCountFull').innerText = alerts.length;

  document.getElementById('alertsOverviewList').innerHTML = alerts.length
    ? alerts.slice(0, 6).map(alertRow).join('')
    : `<p class="text-sm text-slate-500">No threats detected.</p>`;

  document.getElementById('alertsFullList').innerHTML = alerts.length
    ? alerts.map(alertRow).join('')
    : `<p class="text-sm text-slate-500">No threats detected.</p>`;

  // ---- Threat score ----
  let threat = await (await fetch('/threat-score')).json();
  document.getElementById('threatScoreVal').innerText = threat.score;
  const badge = document.getElementById('threatLevelBadge');
  badge.innerText = threat.level;
  badge.className = `text-[11px] px-2 py-0.5 rounded-full font-medium ${levelColor(threat.level)}`;

  // ---- AI Summary ----
  let summary = await (await fetch('/ai-summary')).json();
  document.getElementById('summaryText').innerText = summary.summary;

  // ---- Applications (shared by Overview + Applications tab) ----
  let apps = await (await fetch('/applications')).json();

  document.getElementById('appsOverviewList').innerHTML = apps.length
    ? apps.slice(0, 6).map(a => `
        <div class="flex items-center justify-between text-sm">
          <span class="text-slate-300">${a.app}</span>
          <span class="text-slate-500 text-xs">${a.packets} pkts</span>
        </div>
      `).join('')
    : `<p class="text-sm text-slate-500">No traffic yet.</p>`;

  document.getElementById('appsTable').innerHTML = apps.length
    ? apps.map(a => `
        <tr class="border-b border-white/[0.03] last:border-0">
          <td class="py-2 text-slate-300">${a.app}</td>
          <td class="py-2 text-right text-slate-400">${a.packets.toLocaleString()}</td>
          <td class="py-2 text-right text-slate-400">${a.bytes.toLocaleString()}</td>
        </tr>
      `).join('')
    : `<tr><td colspan="3" class="py-4 text-slate-500">No traffic yet.</td></tr>`;

  // ---- Flows ----
  let flows = await (await fetch('/flows')).json();
  document.getElementById('flowCount').innerText = flows.length;
  document.getElementById('flowsTable').innerHTML = flows.length
    ? flows.map(f => `
        <tr class="border-b border-white/[0.03] last:border-0">
          <td class="py-2 font-mono text-xs text-slate-300">${f.flow}</td>
          <td class="py-2 text-slate-400">${f.application || '—'}</td>
          <td class="py-2 text-slate-400">${f.domain || '—'}</td>
          <td class="py-2 text-right text-slate-400">${f.packets.toLocaleString()}</td>
          <td class="py-2 text-right text-slate-400">${f.bytes.toLocaleString()}</td>
        </tr>
      `).join('')
    : `<tr><td colspan="5" class="py-4 text-slate-500">No active flows.</td></tr>`;

  // ---- Rules ----
  let rules = await (await fetch('/rules')).json();
  document.getElementById('rulesTable').innerHTML = rules.length
    ? rules.map(r => `
        <tr class="border-b border-white/[0.03] last:border-0">
          <td class="py-2 text-slate-300">${r.name}</td>
          <td class="py-2 text-slate-400">${r.port}</td>
          <td class="py-2 text-right"><span class="text-[11px] px-2 py-0.5 rounded-full border ${sevColor(r.severity)}">${r.severity}</span></td>
        </tr>
      `).join('')
    : `<tr><td colspan="3" class="py-4 text-slate-500">No rules loaded.</td></tr>`;
}

// Restore last selected tab, default to overview
setActiveView(localStorage.getItem('netsentinel_view') || 'overview');

refresh();
setInterval(refresh, 3000);
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