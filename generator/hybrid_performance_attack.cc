#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"

#include <fstream>
#include <map>
#include <sstream>

using namespace ns3;

std::ofstream hybridFile;

Ptr<FlowMonitor> monitorPtr;
Ptr<Ipv4FlowClassifier> classifierPtr;

std::map<FlowId, uint64_t> lastTxBytes;
std::map<FlowId, uint64_t> lastRxBytes;
std::map<FlowId, uint32_t> lastLostPackets;

double windowSize = 1.0;
double simTime = 10.0;
double attackStart = 3.0;
double attackStop = 8.0;

uint32_t gSeed = 1;
uint32_t gNTcp = 5;
uint32_t gNAttackers = 50;
// Hard-UDP extension (formerly hybrid_performance_attack_hardudp.cc): benign UDP background
// runs on its own nUdpNormal nodes and the output gains an n_udp_normal column.
bool gDedicatedUdp = false;
uint32_t gNUdpNormal = 3;

uint16_t tcpPort = 5000;
uint16_t udpAttackPort = 6000;
uint16_t udpBgPort = 7000;

std::string gScenarioId = "hybrid_test";
std::string gAttackRate = "1Mbps";
std::string gAttackType = "constant";
std::string gAttackDuration = "long";
std::string gRandomAttackStart = "false";
std::string gBottleneckRate = "50Mbps";
std::string gLinkDelay = "10ms";
uint32_t gPacketSize = 512;
std::string gSeverity = "medium";

std::string MakeSubnet(uint32_t id)
{
    uint32_t second = 10 + (id / 250);
    uint32_t third = 1 + (id % 250);

    std::ostringstream subnet;
    subnet << "10." << second << "." << third << ".0";
    return subnet.str();
}

std::string GetPhase(double now)
{
    if (now <= attackStart)
    {
        return "pre_attack";
    }
    else if (now > attackStart && now <= attackStop)
    {
        return "attack";
    }
    else
    {
        return "post_attack";
    }
}

void RecordHybridWindow()
{
    double now = Simulator::Now().GetSeconds();
    double windowStart = now - windowSize;
    double windowEnd = now;

    std::string phase = GetPhase(now);

    monitorPtr->CheckForLostPackets();
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitorPtr->GetFlowStats();

    for (auto const &flow : stats)
    {
        FlowId flowId = flow.first;
        FlowMonitor::FlowStats st = flow.second;
        Ipv4FlowClassifier::FiveTuple t = classifierPtr->FindFlow(flowId);

        uint64_t prevTx = 0;
        uint64_t prevRx = 0;
        uint32_t prevLost = 0;

        if (lastTxBytes.find(flowId) != lastTxBytes.end())
        {
            prevTx = lastTxBytes[flowId];
            prevRx = lastRxBytes[flowId];
            prevLost = lastLostPackets[flowId];
        }

        uint64_t txWindow = st.txBytes - prevTx;
        uint64_t rxWindow = st.rxBytes - prevRx;
        uint32_t lostWindow = st.lostPackets - prevLost;

        double throughputMbps = (rxWindow * 8.0) / windowSize / 1000000.0;

        double durationSeconds = windowSize;
        double tcpGoodputMbps = 0.0;
        double packetLossRate = 0.0;
        double delaySeconds = 0.0;
        double jitterSeconds = 0.0;

        if (t.protocol == 6)
        {
            tcpGoodputMbps = throughputMbps;
        }

        uint64_t totalPacketsWindow = st.txPackets > 0 ? (st.txPackets) : 0;
        uint64_t rxPacketsWindow = st.rxPackets > 0 ? (st.rxPackets) : 0;

        if (txWindow > 0)
        {
            packetLossRate = (double)lostWindow / ((double)lostWindow + (double)rxPacketsWindow + 1e-9);
        }

        if (st.rxPackets > 0)
        {
            delaySeconds = st.delaySum.GetSeconds() / st.rxPackets;
            jitterSeconds = st.jitterSum.GetSeconds() / st.rxPackets;
        }

        std::string protocol = "OTHER";
        std::string label = "normal";
        std::string severity = "normal";
        int attackFlag = 0;

        if (t.protocol == 6)
        {
            protocol = "TCP";
            label = "normal";
            severity = "normal";
            attackFlag = 0;
        }
        else if (t.protocol == 17)
        {
            protocol = "UDP";

            if (t.destinationPort == udpAttackPort)
            {
                label = "attack";
                severity = gSeverity;
                attackFlag = 1;
            }
            else
            {
                label = "normal";
                severity = "normal";
                attackFlag = 0;
            }
        }

        hybridFile << gScenarioId << ","
                   << gSeed << ","
                   << gNTcp << ","
                   << gNAttackers << ",";
        if (gDedicatedUdp)
        {
            hybridFile << gNUdpNormal << ",";
        }
        hybridFile << gAttackRate << ","
                   << gAttackType << ","
                   << gAttackDuration << ","
                   << attackStart << ","
                   << attackStop << ","
                   << gBottleneckRate << ","
                   << gLinkDelay << ","
                   << gPacketSize << ","
                   << flowId << ","
                   << protocol << ","
                   << t.sourceAddress << ","
                   << t.destinationAddress << ","
                   << t.sourcePort << ","
                   << t.destinationPort << ","
                   << windowStart << ","
                   << windowEnd << ","
                   << txWindow << ","
                   << rxWindow << ","
                   << throughputMbps << ","
                   << lostWindow << ","
                   << durationSeconds << ","
                   << tcpGoodputMbps << ","
                   << packetLossRate << ","
                   << delaySeconds << ","
                   << jitterSeconds << ","
                   << attackFlag << ","
                   << phase << ","
                   << label << ","
                   << severity << "\n";

        lastTxBytes[flowId] = st.txBytes;
        lastRxBytes[flowId] = st.rxBytes;
        lastLostPackets[flowId] = st.lostPackets;
    }

    if (now + windowSize <= simTime)
    {
        Simulator::Schedule(Seconds(windowSize), &RecordHybridWindow);
    }
}

int main(int argc, char *argv[])
{
    uint32_t nTcp = 5;
    uint32_t nAttackers = 50;
    bool dedicatedUdpNodes = false;
    uint32_t nUdpNormal = 3;
    uint32_t seed = 1;
    uint32_t packetSize = 512;

    std::string scenarioId = "hybrid_test";
    std::string attackRate = "1Mbps";
    std::string attackType = "constant";
    std::string attackDuration = "long";
    std::string randomAttackStart = "false";
    std::string bottleneckRate = "50Mbps";
    std::string linkDelay = "10ms";

    CommandLine cmd;
    cmd.AddValue("nTcp", "Number of TCP clients", nTcp);
    cmd.AddValue("nAttackers", "Number of UDP attackers", nAttackers);
    cmd.AddValue("dedicatedUdpNodes", "Hard-UDP extension: benign UDP on its own nUdpNormal nodes", dedicatedUdpNodes);
    cmd.AddValue("nUdpNormal", "Number of benign UDP background nodes (with dedicatedUdpNodes)", nUdpNormal);
    cmd.AddValue("seed", "Simulation seed", seed);
    cmd.AddValue("scenarioId", "Scenario ID", scenarioId);
    cmd.AddValue("attackRate", "UDP attack rate", attackRate);
    cmd.AddValue("attackType", "Attack type: constant, bursty, mixed", attackType);
    cmd.AddValue("attackDuration", "Attack duration: short or long", attackDuration);
    cmd.AddValue("randomAttackStart", "Random attack start: true or false", randomAttackStart);
    cmd.AddValue("bottleneckRate", "Router-server bandwidth", bottleneckRate);
    cmd.AddValue("linkDelay", "Link delay", linkDelay);
    cmd.AddValue("packetSize", "UDP packet size", packetSize);
    cmd.Parse(argc, argv);

    gSeed = seed;
    gNTcp = nTcp;
    gNAttackers = nAttackers;
    gDedicatedUdp = dedicatedUdpNodes;
    gNUdpNormal = nUdpNormal;
    gScenarioId = scenarioId;
    gAttackRate = attackRate;
    gAttackType = attackType;
    gAttackDuration = attackDuration;
    gRandomAttackStart = randomAttackStart;
    gBottleneckRate = bottleneckRate;
    gLinkDelay = linkDelay;
    gPacketSize = packetSize;

    if (nAttackers <= 50)
    {
        gSeverity = "medium";
    }
    else if (nAttackers <= 100)
    {
        gSeverity = "high";
    }
    else
    {
        gSeverity = "very_high";
    }

    // ATTACK_TIMING_LOGIC_ADDED
    // Attack duration and random attack start support
    if (attackDuration == "short")
    {
        attackStop = attackStart + 2.0;
    }
    else if (attackDuration == "long")
    {
        attackStop = attackStart + 5.0;
    }

    if (randomAttackStart == "true")
    {
        Ptr<UniformRandomVariable> attackStartVar = CreateObject<UniformRandomVariable>();
        attackStartVar->SetAttribute("Min", DoubleValue(2.0));
        attackStartVar->SetAttribute("Max", DoubleValue(4.0));

        attackStart = attackStartVar->GetValue();

        if (attackDuration == "short")
        {
            attackStop = attackStart + 2.0;
        }
        else
        {
            attackStop = attackStart + 5.0;
        }

        if (attackStop > simTime - 1.0)
        {
            attackStop = simTime - 1.0;
        }
    }

    RngSeedManager::SetSeed(seed);
    RngSeedManager::SetRun(seed);

    NodeContainer tcpClients;
    tcpClients.Create(nTcp);

    NodeContainer attackers;
    attackers.Create(nAttackers);

    NodeContainer udpNormalClients;
    if (dedicatedUdpNodes)
    {
        udpNormalClients.Create(nUdpNormal);
    }

    Ptr<Node> router = CreateObject<Node>();
    Ptr<Node> server = CreateObject<Node>();

    NodeContainer allNodes;
    allNodes.Add(tcpClients);
    allNodes.Add(attackers);
    if (dedicatedUdpNodes)
    {
        allNodes.Add(udpNormalClients);
    }
    allNodes.Add(router);
    allNodes.Add(server);

    InternetStackHelper stack;
    stack.Install(allNodes);

    PointToPointHelper accessLink;
    accessLink.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    accessLink.SetChannelAttribute("Delay", StringValue(linkDelay));

    PointToPointHelper bottleneckLink;
    bottleneckLink.SetDeviceAttribute("DataRate", StringValue(bottleneckRate));
    bottleneckLink.SetChannelAttribute("Delay", StringValue(linkDelay));

    Ipv4AddressHelper address;
    uint32_t subnetId = 1;

    for (uint32_t i = 0; i < nTcp; i++)
    {
        NodeContainer pair(tcpClients.Get(i), router);
        NetDeviceContainer dev = accessLink.Install(pair);

        std::string subnet = MakeSubnet(subnetId++);
        address.SetBase(subnet.c_str(), "255.255.255.0");
        address.Assign(dev);
    }

    for (uint32_t i = 0; dedicatedUdpNodes && i < nUdpNormal; i++)
    {
        NodeContainer pair(udpNormalClients.Get(i), router);
        NetDeviceContainer dev = accessLink.Install(pair);

        std::string subnet = MakeSubnet(subnetId++);
        address.SetBase(subnet.c_str(), "255.255.255.0");
        address.Assign(dev);
    }

    for (uint32_t i = 0; i < nAttackers; i++)
    {
        NodeContainer pair(attackers.Get(i), router);
        NetDeviceContainer dev = accessLink.Install(pair);

        std::string subnet = MakeSubnet(subnetId++);
        address.SetBase(subnet.c_str(), "255.255.255.0");
        address.Assign(dev);
    }

    NodeContainer routerServer(router, server);
    NetDeviceContainer rsDev = bottleneckLink.Install(routerServer);

    address.SetBase("10.2.1.0", "255.255.255.0");
    Ipv4InterfaceContainer serverIface = address.Assign(rsDev);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    PacketSinkHelper tcpSink("ns3::TcpSocketFactory",
                             InetSocketAddress(Ipv4Address::GetAny(), tcpPort));
    ApplicationContainer tcpSinkApp = tcpSink.Install(server);
    tcpSinkApp.Start(Seconds(0.0));
    tcpSinkApp.Stop(Seconds(simTime));

    PacketSinkHelper udpAttackSink("ns3::UdpSocketFactory",
                                   InetSocketAddress(Ipv4Address::GetAny(), udpAttackPort));
    ApplicationContainer udpAttackSinkApp = udpAttackSink.Install(server);
    udpAttackSinkApp.Start(Seconds(0.0));
    udpAttackSinkApp.Stop(Seconds(simTime));

    PacketSinkHelper udpBgSink("ns3::UdpSocketFactory",
                               InetSocketAddress(Ipv4Address::GetAny(), udpBgPort));
    ApplicationContainer udpBgSinkApp = udpBgSink.Install(server);
    udpBgSinkApp.Start(Seconds(0.0));
    udpBgSinkApp.Stop(Seconds(simTime));

    Ptr<UniformRandomVariable> tcpStartVar = CreateObject<UniformRandomVariable>();
    tcpStartVar->SetAttribute("Min", DoubleValue(0.5));
    tcpStartVar->SetAttribute("Max", DoubleValue(2.5));

    for (uint32_t i = 0; i < nTcp; i++)
    {
        BulkSendHelper tcpSource("ns3::TcpSocketFactory",
                                 InetSocketAddress(serverIface.GetAddress(1), tcpPort));
        tcpSource.SetAttribute("MaxBytes", UintegerValue(0));

        ApplicationContainer app = tcpSource.Install(tcpClients.Get(i));
        app.Start(Seconds(tcpStartVar->GetValue()));
        app.Stop(Seconds(simTime));
    }

    uint32_t bgTcpFlows = std::min(nTcp, (uint32_t)3);

    for (uint32_t i = 0; i < bgTcpFlows; i++)
    {
        OnOffHelper bgTcp("ns3::TcpSocketFactory",
                          InetSocketAddress(serverIface.GetAddress(1), tcpPort));
        bgTcp.SetAttribute("DataRate", StringValue("200Kbps"));
        bgTcp.SetAttribute("PacketSize", UintegerValue(512));
        bgTcp.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        bgTcp.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

        ApplicationContainer bgApp = bgTcp.Install(tcpClients.Get(i));
        bgApp.Start(Seconds(0.2 + i * 0.3));
        bgApp.Stop(Seconds(simTime));
    }

    uint32_t bgUdpFlows = dedicatedUdpNodes ? nUdpNormal : std::min(nTcp, (uint32_t)3);

    for (uint32_t i = 0; i < bgUdpFlows; i++)
    {
        OnOffHelper bgUdp("ns3::UdpSocketFactory",
                          InetSocketAddress(serverIface.GetAddress(1), udpBgPort));
        bgUdp.SetAttribute("DataRate", StringValue("100Kbps"));
        bgUdp.SetAttribute("PacketSize", UintegerValue(256));
        bgUdp.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        bgUdp.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

        ApplicationContainer bgUdpApp =
            bgUdp.Install(dedicatedUdpNodes ? udpNormalClients.Get(i) : tcpClients.Get(i));
        bgUdpApp.Start(Seconds(dedicatedUdpNodes ? 0.5 : 0.4 + i * 0.3));
        bgUdpApp.Stop(Seconds(simTime));
    }

    for (uint32_t i = 0; i < nAttackers; i++)
    {
        OnOffHelper udpAttack("ns3::UdpSocketFactory",
                              InetSocketAddress(serverIface.GetAddress(1), udpAttackPort));
        udpAttack.SetAttribute("DataRate", StringValue(attackRate));
        udpAttack.SetAttribute("PacketSize", UintegerValue(packetSize));

        if (attackType == "constant")
        {
            udpAttack.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
            udpAttack.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        }
        else if (attackType == "bursty")
        {
            udpAttack.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=0.2]"));
            udpAttack.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.3]"));
        }
        else if (attackType == "mixed")
        {
            if (i % 2 == 0)
            {
                udpAttack.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
                udpAttack.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
            }
            else
            {
                udpAttack.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=0.2]"));
                udpAttack.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.3]"));
            }
        }
        else
        {
            udpAttack.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
            udpAttack.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        }

        ApplicationContainer app = udpAttack.Install(attackers.Get(i));
        app.Start(Seconds(attackStart));
        app.Stop(Seconds(attackStop));
    }

    FlowMonitorHelper flowmon;
    monitorPtr = flowmon.InstallAll();
    classifierPtr = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());

    hybridFile.open("results/" + scenarioId + "_hybrid_windows.csv");

    hybridFile << (dedicatedUdpNodes ? "scenario_id,seed,n_tcp,n_attackers,n_udp_normal,attack_rate,"
                                     : "scenario_id,seed,n_tcp,n_attackers,attack_rate,")
               << "attack_type,attack_duration,attack_start,attack_stop,bandwidth,delay,packet_size,flow_id,protocol,src_ip,dst_ip,src_port,dst_port,window_start,window_end,tx_bytes_window,rx_bytes_window,throughput_mbps,lost_packets_window,duration_seconds,tcp_goodput_mbps,packet_loss_rate,delay_seconds,jitter_seconds,attack_flag,phase,label,severity\n";

    Simulator::Schedule(Seconds(windowSize), &RecordHybridWindow);

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    monitorPtr->CheckForLostPackets();

    hybridFile.close();
    Simulator::Destroy();

    std::cout << "Hybrid performance-feature dataset created: results/" << scenarioId << "_hybrid_windows.csv" << std::endl;

    return 0;
}
