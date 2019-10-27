package org.onosproject.install;

import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.GroupId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.*;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.group.Group;
import org.onosproject.net.packet.PacketContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

@Component(
        immediate = true,
        service = FlowRuleInstall.class
)
public class FlowRuleInstall {
    private final Logger log = getLogger(getClass());
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    private ApplicationId appId;

    @Activate
    public void activate(ComponentContext context) {
        appId = coreService.registerApplication("org.onosproject.install");
        log.info("Application FlowRule Install Started", appId.id());
    }

    public TrafficSelector trafficSelector(byte proto, IpPrefix ipSrc, IpPrefix ipDst, TpPort tcpSrcPort, TpPort srcMask, TpPort tcpDstPort, TpPort dstMask) {
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        trafficSelector.matchIPProtocol(proto);
        trafficSelector.matchIPSrc(ipSrc);
        trafficSelector.matchIPDst(ipDst);
        if (proto == IPv4.PROTOCOL_TCP) {
            trafficSelector.matchTcpSrcMasked(tcpSrcPort, srcMask);
            trafficSelector.matchTcpDstMasked(tcpDstPort, dstMask);
        } else if (proto == IPv4.PROTOCOL_UDP) {
            trafficSelector.matchUdpSrcMasked(tcpSrcPort, srcMask);
            trafficSelector.matchUdpDstMasked(tcpDstPort, dstMask);
        }
        return trafficSelector.build();
    }

    public TrafficTreatment outputTreatment(PortNumber portNumber) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .build();
        return treatment;
    }

    public TrafficTreatment tableTreatment(int tableId) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .transition(tableId)
                .build();
        return treatment;
    }

    public TrafficTreatment groupTreatment(GroupId groupId) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .group(groupId)
                .build();
        return treatment;
    }

    public TrafficTreatment dropTreatment(int tableId) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .drop()
                .build();
        return treatment;
    }

    public FlowRule createFlowRule(TrafficTreatment treatment, TrafficSelector selector, DeviceId deviceId, int priority) {
        FlowRule.Builder flowRuleBuilder = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(priority)
                .fromApp(appId)
                .makePermanent();
        return flowRuleBuilder.build();
    }

    /*
        根据数据包来安装流规则，不能安装具有mask的规则
     */
    private void installRule(PacketContext context, int flowPriority, PortNumber portNumber) {
        //
        // We don't support (yet) buffer IDs in the Flow Service so
        // packet out first.
        //
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();


        //
        // If configured and EtherType is IPv4 - Match IPv4 and
        // TCP/UDP/ICMP fields
        //
        if (inPkt.getEtherType() == Ethernet.TYPE_IPV4) {
            IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
            byte ipv4Protocol = ipv4Packet.getProtocol();
            Ip4Prefix matchIp4SrcPrefix =
                    Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                            Ip4Prefix.MAX_MASK_LENGTH);
            Ip4Prefix matchIp4DstPrefix =
                    Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                            Ip4Prefix.MAX_MASK_LENGTH);
            selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPSrc(matchIp4SrcPrefix)
                    .matchIPDst(matchIp4DstPrefix);


            if (ipv4Protocol == IPv4.PROTOCOL_TCP) {
                TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol)
                        .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                        .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
            }
            if (ipv4Protocol == IPv4.PROTOCOL_UDP) {
                UDP udpPacket = (UDP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol)
                        .matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()))
                        .matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
            }
        }


        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .build();

        FlowRule.Builder flowRuleBuilder = DefaultFlowRule.builder()
                .forDevice(context.inPacket().receivedFrom().deviceId())
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(flowPriority)
                .fromApp(appId)
                .makePermanent();

        FlowRuleOperations.Builder flowOpsBuilder = FlowRuleOperations.builder();
        FlowRule tmpFlowRule = flowRuleBuilder.build();
        flowOpsBuilder = flowOpsBuilder.add(tmpFlowRule);

        //初步感觉，冲突检测的代码应该写在apply函数里面
        flowRuleService.apply(flowOpsBuilder.build(new FlowRuleOperationsContext() {
            @Override
            public void onSuccess(FlowRuleOperations ops) {
                // log.info(ops.stages().get(0).)
                log.info("FlowRule安装成功");
            }

            @Override
            public void onError(FlowRuleOperations ops) {
                log.info("流规则安装失败");
            }
        }));
    }

}
