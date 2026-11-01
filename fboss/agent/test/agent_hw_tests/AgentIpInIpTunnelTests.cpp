/*
 *  Copyright (c) 2004-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "fboss/agent/AsicUtils.h"
#include "fboss/agent/gen-cpp2/switch_config_types.h"
#include "fboss/agent/hw/test/ConfigFactory.h"
#include "fboss/agent/hw/test/HwTestCoppUtils.h"
#include "fboss/agent/hw/test/HwTestPacketUtils.h"
#include "fboss/agent/packet/EthFrame.h"
#include "fboss/agent/packet/Ethertype.h"
#include "fboss/agent/packet/IPPacket.h"
#include "fboss/agent/test/AgentHwTest.h"
#include "fboss/agent/test/EcmpSetupHelper.h"
#include "fboss/agent/test/ResourceLibUtil.h"
#include "fboss/agent/test/TestUtils.h"
#include "fboss/agent/test/utils/AclTestUtils.h"
#include "fboss/agent/test/utils/ConfigUtils.h"
#include "fboss/agent/test/utils/PacketSnooper.h"
#include "fboss/agent/test/utils/TrapPacketUtils.h"

namespace facebook::fboss {

class AgentIpInIpTunnelTest : public AgentHwTest {
 protected:
  std::string kTunnelTermDstIp = "2000::1";
  std::vector<ProductionFeature> getProductionFeaturesVerified()
      const override {
    return {ProductionFeature::IP_IN_IP_DECAP};
  }

  cfg::SwitchConfig initialConfig(
      const AgentEnsemble& ensemble) const override {
    auto l3Asics = ensemble.getSw()->getHwAsicTable()->getL3Asics();
    auto asic = checkSameAndGetAsicForTesting(l3Asics);
    auto cfg = utility::oneL3IntfTwoPortConfig(
        ensemble.getSw()->getPlatformMapping(),
        asic,
        ensemble.masterLogicalPortIds()[0],
        ensemble.masterLogicalPortIds()[1],
        ensemble.getSw()->getPlatformSupportsAddRemovePort(),
        asic->desiredLoopbackModes());
    addTunnelConfig(cfg, asic);
    auto port = ensemble.masterLogicalInterfacePortIds()[0];
    utility::addTrapPacketAcl(asic, &cfg, port);
    return cfg;
  }

  void setupHelper() {
    utility::EcmpSetupAnyNPorts6 ecmpHelper(
        getProgrammedState(),
        getSw()->needL2EntryForNeighbor(),
        getLocalMacAddress());
    resolveNeighborAndProgramRoutes(
        ecmpHelper, 1); // forwarding takes the first port: 0
  }

  void learnSrcMacIfPending() {
    auto vlanId =
        VlanID(*initialConfig(*getAgentEnsemble()).vlanPorts()[0].vlanID());
    auto intfMac = utility::getInterfaceMac(getProgrammedState(), vlanId);
    learnL2EntryIfPending(
        utility::MacAddressGenerator().get(intfMac.u64HBO() + 1),
        masterLogicalPortIds()[1]);
  }

  void sendIpInIpPacketPort(
      std::string outDstIpAddr,
      std::string innerDstIpAddr = "3000::3",
      uint8_t outerTrafficClass = 0,
      uint8_t innerTrafficClass = 0) {
    auto txPacket = makePkt(
        outDstIpAddr, innerDstIpAddr, outerTrafficClass, innerTrafficClass);
    getAgentEnsemble()->ensureSendPacketOutOfPort(
        std::move(txPacket), masterLogicalPortIds()[1]);
  }

 private:
  void addTunnelConfig(cfg::SwitchConfig& cfg, const HwAsic* asic) const {
    std::vector<cfg::IpInIpTunnel> tunnelList;
    tunnelList.push_back(makeTunnelConfig(
        "hwTestTunnel",
        kTunnelTermDstIp,
        (InterfaceID)cfg.interfaces()[0].intfID().value(),
        asic));
    cfg.ipInIpTunnels() = tunnelList;
  }

  cfg::IpInIpTunnel makeTunnelConfig(
      std::string name,
      std::string dstIp,
      InterfaceID interfaceId,
      const HwAsic* asic) const {
    cfg::IpInIpTunnel tunnel;
    tunnel.ipInIpTunnelId() = name;
    tunnel.underlayIntfID() = interfaceId;
    // in brcm-sai: masks are not supported
    tunnel.dstIp() = dstIp;
    tunnel.tunnelTermType() = cfg::TunnelTerminationType::P2MP;
    tunnel.tunnelType() = TunnelType::IP_IN_IP_DECAP;
    tunnel.ttlMode() = cfg::TunnelMode::PIPE;
    tunnel.dscpMode() = asic->getTunnelDscpMode();
    tunnel.ecnMode() = cfg::TunnelMode::PIPE;

    return tunnel;
  }

  std::unique_ptr<TxPacket> makePkt(
      std::string outerDstIpAddr,
      std::string innerDstIpAddr = "3000::3",
      uint8_t outerTrafficClass = 0,
      uint8_t innerTrafficClass = 0) {
    auto vlanId =
        VlanID(*initialConfig(*getAgentEnsemble()).vlanPorts()[0].vlanID());
    auto intfMac = utility::getInterfaceMac(getProgrammedState(), vlanId);
    auto srcMac = utility::MacAddressGenerator().get(intfMac.u64HBO() + 1);
    const folly::IPAddressV6 outerSrcIp("1000::1");
    const folly::IPAddressV6 outerDstIp(outerDstIpAddr);
    const folly::IPAddressV6 innerSrcIp("4004::23");
    const folly::IPAddressV6 innerDstIp(innerDstIpAddr);
    auto payload = std::vector<uint8_t>(10, 0xff);
    return utility::makeIpInIpTxPacket(
        getSw(),
        vlanId,
        srcMac, // src mac
        intfMac, // dst mac
        outerSrcIp,
        outerDstIp,
        innerSrcIp,
        innerDstIp,
        10000, // udp src port
        20000, // udp dst port
        outerTrafficClass,
        innerTrafficClass,
        255,
        std::nullopt,
        0,
        payload);
  }
};

TEST_F(AgentIpInIpTunnelTest, TunnelDecapForwarding) {
  auto setup = [=, this]() { setupHelper(); };
  auto verify = [=, this]() {
    learnSrcMacIfPending();
    auto beforeInBytes =
        getLatestPortStats(masterLogicalPortIds()[1]).inBytes_().value();
    auto beforeOutBytes =
        getLatestPortStats(masterLogicalPortIds()[0]).outBytes_().value();
    sendIpInIpPacketPort(kTunnelTermDstIp);
    auto afterInBytes =
        getLatestPortStats(masterLogicalPortIds()[1]).inBytes_().value();
    auto afterOutBytes =
        getLatestPortStats(masterLogicalPortIds()[0]).outBytes_().value();

    EXPECT_EQ(
        afterInBytes - beforeInBytes - IPv6Hdr::SIZE,
        afterOutBytes - beforeOutBytes);
  };
  verifyAcrossWarmBoots(setup, verify);
}

TEST_F(AgentIpInIpTunnelTest, TunnelTermEntryMiss) {
  auto setup = [=, this]() { setupHelper(); };
  auto verify = [=, this]() {
    learnSrcMacIfPending();
    auto beforeInBytes =
        getLatestPortStats(masterLogicalPortIds()[1]).inBytes_().value();
    auto beforeOutBytes =
        getLatestPortStats(masterLogicalPortIds()[0]).outBytes_().value();
    sendIpInIpPacketPort("5000::6");
    auto afterInBytes =
        getLatestPortStats(masterLogicalPortIds()[1]).inBytes_().value();
    auto afterOutBytes =
        getLatestPortStats(masterLogicalPortIds()[0]).outBytes_().value();

    EXPECT_NE(afterInBytes, beforeInBytes);
    EXPECT_NE(afterOutBytes, beforeOutBytes);
    EXPECT_EQ(afterInBytes - beforeInBytes, afterOutBytes - beforeOutBytes);
  };
  verifyAcrossWarmBoots(setup, verify);
}

TEST_F(AgentIpInIpTunnelTest, IpinIpNoTunnelConfigured) {
  auto setup = [=, this]() {
    auto ensemble = getAgentEnsemble();
    auto l3Asics = ensemble->getSw()->getHwAsicTable()->getL3Asics();
    auto asic = checkSameAndGetAsicForTesting(l3Asics);
    auto cfg = utility::oneL3IntfTwoPortConfig(
        ensemble->getSw()->getPlatformMapping(),
        asic,
        ensemble->masterLogicalPortIds()[0],
        ensemble->masterLogicalPortIds()[1],
        ensemble->getSw()->getPlatformSupportsAddRemovePort(),
        asic->desiredLoopbackModes());
    //  no tunnel configured
    applyNewConfig(cfg);
    setupHelper();
  };

  auto verify = [=, this]() {
    learnSrcMacIfPending();
    auto beforeInBytes =
        getLatestPortStats(masterLogicalPortIds()[1]).inBytes_().value();
    auto beforeOutBytes =
        getLatestPortStats(masterLogicalPortIds()[0]).outBytes_().value();
    sendIpInIpPacketPort("5000::6");
    auto afterInBytes =
        getLatestPortStats(masterLogicalPortIds()[1]).inBytes_().value();
    auto afterOutBytes =
        getLatestPortStats(masterLogicalPortIds()[0]).outBytes_().value();

    EXPECT_NE(afterInBytes, beforeInBytes);
    EXPECT_NE(afterOutBytes, beforeOutBytes);
    EXPECT_EQ(afterInBytes - beforeInBytes, afterOutBytes - beforeOutBytes);
  };
  verifyAcrossWarmBoots(setup, verify);
}

TEST_F(AgentIpInIpTunnelTest, DecapPacketParsing) {
  auto setup = [=, this]() { setupHelper(); };
  auto verify = [=, this]() {
    learnSrcMacIfPending();
    auto ensemble = getAgentEnsemble();
    auto l3Asics = ensemble->getSw()->getHwAsicTable()->getL3Asics();
    auto asic = checkSameAndGetAsicForTesting(l3Asics);

    utility::SwSwitchPacketSnooper snooper(getSw(), "snooper");
    sendIpInIpPacketPort(kTunnelTermDstIp, "dead::1", 0xFA, 0xCE);
    auto capturedPktBuf = snooper.waitForPacket(1);
    ASSERT_TRUE(capturedPktBuf.has_value());

    folly::io::Cursor capturedPktCursor{capturedPktBuf->get()};
    auto capturedPkt = utility::EthFrame(capturedPktCursor);
    auto v6Pkt = capturedPkt.v6PayLoad();
    auto hdr = v6Pkt->header();
    EXPECT_EQ(hdr.dstAddr, folly::IPAddress("dead::1"));
    EXPECT_EQ(hdr.srcAddr, folly::IPAddress("4004::23"));

    if (cfg::TunnelMode::PIPE == asic->getTunnelDscpMode()) {
      // using PIPE mode: inner DSCP and ECN should not be changed
      EXPECT_EQ(hdr.trafficClass, 0xCE);
    } else {
      // using UNIFORM mode: Where the DSCP field is preserved end-to-end by
      // copying into the outer header on encapsulation and copying from the
      // outer header on decapsulation.
      EXPECT_EQ(hdr.trafficClass, 0xF8);
    }

    auto udpPkt = v6Pkt->udpPayload();
    auto payload = udpPkt->payload();
    EXPECT_EQ(payload.size(), 10);
    EXPECT_EQ(payload, std::vector<uint8_t>(10, 0xff));
    EXPECT_EQ(udpPkt->header().srcPort, 10000);
    EXPECT_EQ(udpPkt->header().dstPort, 20000);
  };
  verifyAcrossWarmBoots(setup, verify);
}
class AgentIpInIpEncapTunnelTest : public AgentHwTest {
 public:
  void setCmdLineFlagOverrides() const override {
    AgentHwTest::setCmdLineFlagOverrides();
    FLAGS_enable_acl_table_redirect_action = true;
  }

 protected:
  std::string kEncapSrcIp = "2401:db00::1";
  std::string kEncapDstIp = "2401:db00:ffff::1";
  std::string kTargetPrefix = "2403:300::";
  int kTargetPrefixLen = 32;
  std::string kV4TargetPrefix = "100.0.0.0/24";

  std::vector<ProductionFeature> getProductionFeaturesVerified()
      const override {
    return {ProductionFeature::IP_IN_IP_ENCAP};
  }

  cfg::SwitchConfig initialConfig(
      const AgentEnsemble& ensemble) const override {
    auto l3Asics = ensemble.getSw()->getHwAsicTable()->getL3Asics();
    auto asic = checkSameAndGetAsicForTesting(l3Asics);
    std::vector<PortID> ports = {
        ensemble.masterLogicalPortIds()[0],
        ensemble.masterLogicalPortIds()[1],
        ensemble.masterLogicalPortIds()[2],
    };
    auto cfg = utility::onePortPerInterfaceConfig(
        ensemble.getSw(), ports, true /*interfaceHasSubnet*/);
    addEncapTunnelConfig(cfg);
    addEncapAclConfig(cfg, asic, ensemble);
    return cfg;
  }

  void addEncapTunnelConfig(cfg::SwitchConfig& cfg) const {
    cfg::IpInIpTunnel tunnel;
    tunnel.ipInIpTunnelId() = "encapTunnel0";
    tunnel.underlayIntfID() = *cfg.interfaces()[0].intfID();
    tunnel.srcIp() = kEncapSrcIp;
    tunnel.dstIp() = kEncapDstIp;
    tunnel.tunnelType() = TunnelType::IP_IN_IP_ENCAP;
    tunnel.ttlMode() = cfg::TunnelMode::UNIFORM;
    tunnel.dscpMode() = cfg::TunnelMode::UNIFORM;
    tunnel.ecnMode() = cfg::TunnelMode::UNIFORM;
    cfg.ipInIpTunnels() = {tunnel};
  }

  void addEncapAclConfig(
      cfg::SwitchConfig& cfg,
      const HwAsic* asic,
      const AgentEnsemble& ensemble) const {
    cfg::AclEntry acl;
    acl.name() = "acl_encap";
    acl.dstIp() = kTargetPrefix + "/" + std::to_string(kTargetPrefixLen);
    acl.proto() = 6;
    acl.l4DstPort() = 443;
    utility::addAcl(&cfg, acl, cfg::AclStage::INGRESS);

    cfg::MatchAction action;
    cfg::RedirectToNextHopAction redirectAction;
    cfg::RedirectNextHop nh;
    nh.ip() = kEncapDstIp;
    nh.tunnelType() = TunnelType::IP_IN_IP_ENCAP;
    nh.tunnelId() = "encapTunnel0";
    redirectAction.redirectNextHops() = {nh};
    action.redirectToNextHop() = redirectAction;

    cfg::MatchToAction mta;
    mta.matcher() = "acl_encap";
    mta.action() = action;
    if (!cfg.dataPlaneTrafficPolicy().has_value()) {
      cfg.dataPlaneTrafficPolicy() = cfg::TrafficPolicyConfig();
    }
    cfg.dataPlaneTrafficPolicy()->matchToAction()->push_back(mta);

    cfg::AclEntry aclV4;
    aclV4.name() = "acl_encap_v4";
    aclV4.dstIp() = kV4TargetPrefix;
    aclV4.proto() = 6;
    aclV4.l4DstPort() = 443;
    utility::addAcl(&cfg, aclV4, cfg::AclStage::INGRESS);

    cfg::MatchToAction mtaV4;
    mtaV4.matcher() = "acl_encap_v4";
    mtaV4.action() = action;
    cfg.dataPlaneTrafficPolicy()->matchToAction()->push_back(mtaV4);

    utility::addTrapPacketAcl(
        asic,
        &cfg,
        std::set<PortID>{
            ensemble.masterLogicalPortIds()[1],
            ensemble.masterLogicalPortIds()[2]});
  }

  void setupRouteToPort(
      const PortID& portID,
      const folly::IPAddressV6& dstIp,
      uint8_t prefixLen) {
    utility::EcmpSetupTargetedPorts6 ecmpHelper{
        getProgrammedState(), getSw()->needL2EntryForNeighbor()};
    auto dstPort = PortDescriptor(portID);
    applyNewState([&](const std::shared_ptr<SwitchState>& in) {
      return ecmpHelper.resolveNextHops(in, {dstPort});
    });
    auto wrapper = getSw()->getRouteUpdater();
    ecmpHelper.programRoutes(
        &wrapper,
        {dstPort},
        {RoutePrefix<folly::IPAddressV6>{dstIp, prefixLen}});
  }

  void setupHelper() {
    auto ports = masterLogicalPortIds();
    // Encap outer dst IP → port 1 (encap egress)
    setupRouteToPort(ports[1], folly::IPAddressV6(kEncapDstIp), 64);
    // Default route → port 2 (non-encap egress)
    setupRouteToPort(ports[2], folly::IPAddressV6(), 0);
  }

  std::unique_ptr<TxPacket> makeTcpPacket(
      std::string dstIp = "2403:300::1",
      uint16_t dstPort = 443,
      uint8_t trafficClass = 0) {
    auto vlanId =
        VlanID(*initialConfig(*getAgentEnsemble()).vlanPorts()[0].vlanID());
    auto intfMac = utility::getInterfaceMac(getProgrammedState(), vlanId);
    return utility::makeTCPTxPacket(
        getSw(),
        vlanId,
        intfMac,
        folly::IPAddress(dstIp),
        10000,
        dstPort,
        trafficClass);
  }

  void sendEncapPacket(bool cpuInject, std::unique_ptr<TxPacket> pkt) {
    if (cpuInject) {
      getAgentEnsemble()->ensureSendPacketSwitched(std::move(pkt));
    } else {
      getAgentEnsemble()->ensureSendPacketOutOfPort(
          std::move(pkt), masterLogicalPortIds()[0]);
    }
  }

  void verifyEncapPacketParsing(bool isV4, bool cpuInject) {
    constexpr uint8_t kDscp{48};
    // makeTcpPacket builds the inner packet with hop limit / TTL 255.
    // Forwarding decrements it once, so under the UNIFORM TTL mode both
    // the inner header and the outer header carry 254.
    constexpr uint8_t kExpectedHopLimit{254};
    const std::string dstIp = isV4 ? "100.0.0.1" : "2403:300::1";
    utility::SwSwitchPacketSnooper snooper(getSw(), "snooper");
    auto txPacket = makeTcpPacket(dstIp, 443, kDscp);
    // makeEthFrame applies the same forwarding decrement to its copy,
    // so the expected inner packet already carries the decremented
    // hop limit / TTL.
    const auto origFrame = utility::makeEthFrame(*txPacket);
    sendEncapPacket(cpuInject, std::move(txPacket));
    auto capturedPktBuf = snooper.waitForPacket(1);
    ASSERT_TRUE(capturedPktBuf.has_value());

    folly::io::Cursor capturedPktCursor{capturedPktBuf->get()};
    auto capturedPkt = utility::EthFrame(capturedPktCursor);
    EXPECT_EQ(
        capturedPkt.header().etherType,
        static_cast<uint16_t>(ETHERTYPE::ETHERTYPE_IPV6));
    auto v6Pkt = capturedPkt.v6PayLoad();
    ASSERT_TRUE(v6Pkt.has_value());
    auto outerHdr = v6Pkt->header();

    EXPECT_EQ(outerHdr.srcAddr, folly::IPAddress(kEncapSrcIp));
    EXPECT_EQ(outerHdr.dstAddr, folly::IPAddress(kEncapDstIp));
    EXPECT_EQ(outerHdr.nextHeader, isV4 ? 4 : 41);
    EXPECT_EQ(outerHdr.trafficClass >> 2, kDscp);
    EXPECT_EQ(outerHdr.trafficClass & 0x3, 0);
    EXPECT_EQ(outerHdr.hopLimit, kExpectedHopLimit);

    if (isV4) {
      const auto origInnerPkt = origFrame.v4PayLoad();
      ASSERT_TRUE(origInnerPkt.has_value());
      const auto* innerPkt = v6Pkt->v4PayLoad();
      ASSERT_TRUE(innerPkt != nullptr);
      const auto innerHdr = innerPkt->header();
      EXPECT_EQ(innerHdr.dstAddr, folly::IPAddressV4("100.0.0.1"));
      EXPECT_EQ(innerHdr.srcAddr, folly::IPAddressV4("1.1.1.2"));
      EXPECT_EQ(innerHdr.protocol, 6);
      EXPECT_EQ(innerHdr.dscp, kDscp);
      EXPECT_EQ(innerHdr.ecn, 0);
      EXPECT_EQ(innerHdr.ttl, kExpectedHopLimit);
      // The inner packet must survive encapsulation with only the TTL
      // changed: header, TCP header, and payload equal the original.
      EXPECT_EQ(*innerPkt, *origInnerPkt);
    } else {
      const auto origInnerPkt = origFrame.v6PayLoad();
      ASSERT_TRUE(origInnerPkt.has_value());
      const auto* innerPkt = v6Pkt->v6PayLoad();
      ASSERT_TRUE(innerPkt != nullptr);
      EXPECT_EQ(innerPkt->header().hopLimit, kExpectedHopLimit);
      // The inner packet must survive encapsulation with only the hop
      // limit changed: header, TCP header, and payload equal the
      // original packet.
      EXPECT_EQ(*innerPkt, *origInnerPkt);
    }
  }
};

TEST_F(AgentIpInIpEncapTunnelTest, EncapTunnelForwarding) {
  auto setup = [=, this]() { setupHelper(); };
  auto verify = [=, this]() {
    int64_t frontPanelEncapDeltaV4 = 0;
    int64_t frontPanelEncapDeltaV6 = 0;
    for (bool isV4 : {false, true}) {
      for (bool cpuInject : {false, true}) {
        auto beforeInBytes =
            getLatestPortStats(masterLogicalPortIds()[0]).inBytes_().value();
        auto beforeEncapOutBytes =
            getLatestPortStats(masterLogicalPortIds()[1]).outBytes_().value();
        auto beforeNonEncapOutBytes =
            getLatestPortStats(masterLogicalPortIds()[2]).outBytes_().value();
        sendEncapPacket(
            cpuInject, makeTcpPacket(isV4 ? "100.0.0.1" : "2403:300::1"));
        auto afterInBytes =
            getLatestPortStats(masterLogicalPortIds()[0]).inBytes_().value();
        auto afterEncapOutBytes =
            getLatestPortStats(masterLogicalPortIds()[1]).outBytes_().value();
        auto afterNonEncapOutBytes =
            getLatestPortStats(masterLogicalPortIds()[2]).outBytes_().value();
        auto encapDelta = afterEncapOutBytes - beforeEncapOutBytes;
        auto nonEncapDelta = afterNonEncapOutBytes - beforeNonEncapOutBytes;
        if (!cpuInject) {
          // Encapped packet exits encap egress port (port 1) with added
          // outer header.
          EXPECT_EQ(afterInBytes - beforeInBytes + IPv6Hdr::SIZE, encapDelta);
          // Non-encap egress port (port 2) should see no traffic.
          EXPECT_EQ(nonEncapDelta, 0);
          if (isV4) {
            frontPanelEncapDeltaV4 = encapDelta;
          } else {
            frontPanelEncapDeltaV6 = encapDelta;
          }
        } else {
          // CPU-injected packets do not ingress a front-panel port, so
          // port 0 inBytes does not move. The encap egress delta must
          // match the front-panel delta for the same packet.
          EXPECT_GT(encapDelta, 0);
          EXPECT_EQ(
              encapDelta,
              isV4 ? frontPanelEncapDeltaV4 : frontPanelEncapDeltaV6);
          EXPECT_EQ(nonEncapDelta, 0);
        }
      }
    }
  };
  verifyAcrossWarmBoots(setup, verify);
}

TEST_F(AgentIpInIpEncapTunnelTest, EncapAclMiss) {
  auto setup = [=, this]() { setupHelper(); };
  auto verify = [=, this]() {
    for (bool isV4 : {false, true}) {
      for (bool cpuInject : {false, true}) {
        auto beforeInBytes =
            getLatestPortStats(masterLogicalPortIds()[0]).inBytes_().value();
        auto beforeEncapOutBytes =
            getLatestPortStats(masterLogicalPortIds()[1]).outBytes_().value();
        auto beforeNonEncapOutBytes =
            getLatestPortStats(masterLogicalPortIds()[2]).outBytes_().value();
        sendEncapPacket(
            cpuInject, makeTcpPacket(isV4 ? "100.0.1.1" : "2620:0:1::1"));
        auto afterInBytes =
            getLatestPortStats(masterLogicalPortIds()[0]).inBytes_().value();
        auto afterEncapOutBytes =
            getLatestPortStats(masterLogicalPortIds()[1]).outBytes_().value();
        auto afterNonEncapOutBytes =
            getLatestPortStats(masterLogicalPortIds()[2]).outBytes_().value();
        // A missed packet must never be encapped.
        EXPECT_EQ(afterEncapOutBytes, beforeEncapOutBytes);
        if (!isV4 && !cpuInject) {
          EXPECT_NE(afterInBytes, beforeInBytes);
          // Non-encapped packet exits non-encap egress port (port 2,
          // default route).
          EXPECT_NE(afterNonEncapOutBytes, beforeNonEncapOutBytes);
          EXPECT_EQ(
              afterInBytes - beforeInBytes,
              afterNonEncapOutBytes - beforeNonEncapOutBytes);
        } else if (!isV4) {
          // CPU-injected packets do not move port 0 inBytes, but the
          // missed packet must still egress unencapped on port 2.
          EXPECT_NE(afterNonEncapOutBytes, beforeNonEncapOutBytes);
        } else if (!cpuInject) {
          // No IPv4 default route is programmed, so only the no-encap
          // property is asserted for IPv4 misses.
          EXPECT_NE(afterInBytes, beforeInBytes);
        }
      }
    }
  };
  verifyAcrossWarmBoots(setup, verify);
}

TEST_F(AgentIpInIpEncapTunnelTest, EncapPacketParsing) {
  auto setup = [=, this]() { setupHelper(); };
  auto verify = [=, this]() {
    for (bool isV4 : {false, true}) {
      for (bool cpuInject : {false, true}) {
        verifyEncapPacketParsing(isV4, cpuInject);
      }
    }
  };
  verifyAcrossWarmBoots(setup, verify);
}

} // namespace facebook::fboss
