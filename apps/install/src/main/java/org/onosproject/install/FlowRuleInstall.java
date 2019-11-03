package org.onosproject.install;

import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.GroupId;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.conflict.ConflictCheck;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.group.Group;
import org.onosproject.net.packet.PacketContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.util.List;
import java.util.Set;

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
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;


    private ApplicationId appId;

    private DeviceId deviceId;

    @Activate
    public void activate(ComponentContext context) {
        appId = coreService.registerApplication("org.onosproject.install");
        log.info("Application FlowRule Install Started", appId.id());
    }

    public void runTest(int conflictFields) {
        initDevice();
        //首先生成并下发一个字段相交的规则
        if (conflictFields == 1) {
            clearTimes();
            flowRuleService.purgeFlowRules(deviceId);
            generateFlowRule1();
        } else if (conflictFields == 2) {
            clearTimes();
            flowRuleService.purgeFlowRules(deviceId);
            generateFlowRule2();
        } else if (conflictFields == 3) {
            clearTimes();
            flowRuleService.purgeFlowRules(deviceId);
            generateFlowRule3();
        } else if (conflictFields == 0) {
            clearTimes();
            flowRuleService.purgeFlowRules(deviceId);
            generateFlowRule();
        } else {
            clearTimes();
            flowRuleService.purgeFlowRules(deviceId);
            generateFlowRule();
        }
        //生成并下发两个字段相交或的规则
        //生成三个字段相交的规则
    }

    private void initDevice() {
        Iterable<Device> iterater = deviceService.getAvailableDevices();
        for (Device device : iterater) {
            deviceId = device.id();
            break;
        }
    }

    public List<Long> getTimes() {
        return flowRuleService.getTimes();
    }

    public void clearTimes() {
        flowRuleService.getTimes().clear();
    }


    public TrafficSelector trafficSelector(byte proto, IpPrefix ipSrc, IpPrefix ipDst, TpPort tcpSrcPort, TpPort srcMask, TpPort tcpDstPort, TpPort dstMask) {
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        trafficSelector.matchIPProtocol(proto);
        trafficSelector.matchIPSrc(ipSrc);
        trafficSelector.matchEthType(Ethernet.TYPE_IPV4);
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

    public TrafficTreatment dropTreatment() {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .drop()
                .build();
        return treatment;
    }

    public FlowRule createFlowRule(TrafficTreatment treatment, TrafficSelector selector, DeviceId deviceId, int priority, int tableId) {
        FlowRule.Builder flowRuleBuilder = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(priority)
                .fromApp(appId)
                .makePermanent();
        return flowRuleBuilder.build();
    }

    public void installFlowRule(FlowRule tmpFlowRule) {
        FlowRuleOperations.Builder flowOpsBuilder = FlowRuleOperations.builder();
        flowOpsBuilder = flowOpsBuilder.add(tmpFlowRule);

        flowRuleService.apply(flowOpsBuilder.build(new FlowRuleOperationsContext() {
            @Override
            public void onSuccess(FlowRuleOperations ops) {
            }

            @Override
            public void onError(FlowRuleOperations ops) {
                log.info("流规则安装失败");
                List<Set<FlowRuleOperation>> stages = ops.stages();
                for (Set<FlowRuleOperation> flowRuleSet : stages) {
                    for (FlowRuleOperation flowRuleOp : flowRuleSet) {
                        FlowRule tmpRule = flowRuleOp.rule();
                        log.info(tmpRule.toString());
                    }
                }
            }
        }));
    }

    public void generateFlowRule() {
        IpPrefix ipSrcPrefix;
        IpPrefix ipDstPrefix = Ip4Prefix.valueOf(Ip4Address.valueOf("192.168.103.104"), 32);
        byte proto;
        TpPort tcpSrc = TpPort.tpPort(1024);
        TpPort tcpSrcMask = TpPort.tpPort(0xFFFF);
        TpPort tcpDst = TpPort.tpPort(1024);
        TpPort tcpDstMask = TpPort.tpPort(0xFFFF);
        TrafficSelector trafficSelector;
        TrafficTreatment trafficTreatment;
        FlowRule flowRule;

        for (int i = 1; i <= 10; i++) {
            for (int j = 1; j <= 100; j++) {
                proto = IPv4.PROTOCOL_TCP;
                ipSrcPrefix = Ip4Prefix.valueOf(Ip4Address.valueOf("192.168." + i + "." + j), 32);
                trafficSelector = trafficSelector(proto, ipSrcPrefix, ipDstPrefix, tcpSrc, tcpSrcMask, tcpDst, tcpDstMask);
                trafficTreatment = outputTreatment(PortNumber.portNumber((int) (Math.random() * 100)));
                flowRule = createFlowRule(trafficTreatment, trafficSelector, deviceId, 40, 0);
                installFlowRule(flowRule);
            }
        }
    }

    /*
        生成1000条规则，并安装在表0
     */
    public void generateFlowRule1() {
        IpPrefix ipSrcPrefix = Ip4Prefix.valueOf(Ip4Address.valueOf("192.168.1.1"), 16);
        IpPrefix ipDstPrefix = Ip4Prefix.valueOf(Ip4Address.valueOf("192.168.103.104"), 32);
        byte proto = IPv4.PROTOCOL_TCP;
        TpPort tcpSrc = TpPort.tpPort(1024);
        TpPort tcpSrcMask = TpPort.tpPort(0xFFFF);
        TpPort tcpDst = TpPort.tpPort(1024);
        TpPort tcpDstMask = TpPort.tpPort(0xFFFF);
        TrafficSelector trafficSelector = trafficSelector(proto, ipSrcPrefix, ipDstPrefix, tcpSrc, tcpSrcMask, tcpDst, tcpDstMask);
        TrafficTreatment trafficTreatment = outputTreatment(PortNumber.portNumber(666));
        FlowRule flowRule = createFlowRule(trafficTreatment, trafficSelector, deviceId, 40, 0);
        installFlowRule(flowRule);
        int count = 0;
        for (int i = 1; i <= 10; i++) {
            for (int j = 1; j <= 100; j++) {
                int random = (int) (Math.random() * 10);
                if (random % 2 == 0) {
                    proto = IPv4.PROTOCOL_TCP;
                } else {
                    proto = IPv4.PROTOCOL_UDP;
                }
                ipSrcPrefix = Ip4Prefix.valueOf(Ip4Address.valueOf("192.168." + i + "." + j), 32);
                trafficSelector = trafficSelector(proto, ipSrcPrefix, ipDstPrefix, tcpSrc, tcpSrcMask, tcpDst, tcpDstMask);
                trafficTreatment = outputTreatment(PortNumber.portNumber((int) (Math.random() * 100)));
                flowRule = createFlowRule(trafficTreatment, trafficSelector, DeviceId.deviceId("of:0000000000000001"), 40, 0);
                installFlowRule(flowRule);
                count++;
            }
        }
        log.info("Install FlowRules " + count);
    }

    public void generateFlowRule2() {
        IpPrefix ipSrcPrefix = Ip4Prefix.valueOf(Ip4Address.valueOf("192.168.1.1"), 16);
        IpPrefix ipDstPrefix = Ip4Prefix.valueOf(Ip4Address.valueOf("192.168.103.104"), 32);
        byte proto = IPv4.PROTOCOL_TCP;
        TpPort tcpSrc = TpPort.tpPort(1024);
        TpPort tcpSrcMask = TpPort.tpPort(0xFFFF);
        TpPort tcpDst = TpPort.tpPort(1024);
        TpPort tcpDstMask = TpPort.tpPort(0xFFFF);
        TrafficSelector trafficSelector = trafficSelector(proto, ipSrcPrefix, ipDstPrefix, tcpSrc, tcpSrcMask, tcpDst, tcpDstMask);
        TrafficTreatment trafficTreatment = outputTreatment(PortNumber.portNumber(666));
        FlowRule flowRule = createFlowRule(trafficTreatment, trafficSelector, deviceId, 40, 0);
        installFlowRule(flowRule);
        int tableId = (int) (Math.random() * 10) % 10;
        int count = 0;
        for (int i = 1; i <= 10; i++) {
            for (int j = 1; j <= 100; j++) {
                int random = (int) (Math.random() * 10);
                if (random % 2 == 0) {
                    proto = IPv4.PROTOCOL_TCP;
                } else {
                    proto = IPv4.PROTOCOL_UDP;
                }
                ipSrcPrefix = Ip4Prefix.valueOf(Ip4Address.valueOf("192.168." + i + "." + j), 32);
                trafficSelector = trafficSelector(proto, ipSrcPrefix, ipDstPrefix, tcpSrc, tcpSrcMask, tcpDst, tcpDstMask);
                trafficTreatment = outputTreatment(PortNumber.portNumber((int) (Math.random() * 100)));
                flowRule = createFlowRule(trafficTreatment, trafficSelector, DeviceId.deviceId("of:0000000000000001"), 40, tableId);
                installFlowRule(flowRule);
                count++;
            }
        }
        log.info("Install FlowRules " + count);
    }

    public void generateFlowRule3() {

    }
}
