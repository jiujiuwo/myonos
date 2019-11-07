package org.onosproject.net.flow.conflict;

import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.*;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.List;

public class ConflictCheck {

    public enum relations {
        UNKNOWN,
        EXACT,
        SUBSET,
        CORRELATED,
        SUPERSET
    }

    public enum anomals {
        DISJOINT,
        CORRELATION,
        REDUNDANCY,
        GENERALIZATION,
        SHADOWING
    }


    /*  基于字段范围的检测方法
        如果交集为空，则返回0
        如果交集非空，部分相交返回1，Rx包含Ry返回2，Ry包含Rx返回3
     */
    public static anomals filedRangeConflictCheck(FlowRule rxFlowRule, FlowRule ryFLowRule, int algorithmChosen) {
        relations relation = relations.UNKNOWN;//0 unknown,1 exact, 2 subset,3 superset, 4 intersectant
        boolean insCon = false;
        if (algorithmChosen == 1) {
            List<String> rxList = getFiveTupleOfFlowRule(rxFlowRule);
            List<String> ryList = getFiveTupleOfFlowRule(ryFLowRule);
            for (int i = 0; i < rxList.size(); i++) {
                if (rxList.get(i).equals(ryList.get(i))) {
                    if (relation == relations.UNKNOWN) {
                        relation = relations.EXACT;
                    }
                    //如果Ry包含Rx,即交集为Rx,sameWithRx
                } else if (HeaderSpaceUtil.headerSpaceUnion(rxList.get(i), ryList.get(i)) == 2) {
                    if (relation == relations.SUBSET || relation == relations.CORRELATED) {
                        relation = relation.CORRELATED;
                    } else {
                        relation = relations.SUPERSET;
                    }
                    //如果Rx包含Ry,即交集为Ry,sameWithRx
                } else if (HeaderSpaceUtil.headerSpaceUnion(rxList.get(i), ryList.get(i)) == 3) {
                    if (relation == relations.SUPERSET || relation == relations.CORRELATED) {
                        relation = relations.CORRELATED;
                    } else {
                        relation = relations.SUBSET;
                    }
                } else {
                    return anomals.DISJOINT;
                }
            }
            insCon = instructionConflictCheckOld(rxFlowRule, ryFLowRule);

        } else if (algorithmChosen == 2) {
            int result = HeaderSpaceUtil.headerSpaceConflictCheck(rxFlowRule.getHsBytes(), ryFLowRule.getHsBytes());
            if (result == 1) {
                relation = relations.CORRELATED;
            } else if (result == 3) {
                relation = relations.SUBSET;
            } else if (result == 2) {
                relation = relations.SUPERSET;
            } else if (result == 4) {
                relation = relations.EXACT;
            }
            insCon = instructionConflictCheck(rxFlowRule, ryFLowRule);
        }

        if (relation == relations.CORRELATED && insCon) {
            return anomals.CORRELATION;
        } else if (relation == relations.SUPERSET) {
            if (!insCon) {
                return anomals.REDUNDANCY;
            } else {
                return anomals.GENERALIZATION;
            }
        } else if (relation == relations.SUBSET || relation == relations.EXACT) {
            if (!insCon) {
                return anomals.REDUNDANCY;
            } else {
                return anomals.SHADOWING;
            }
        }

        return anomals.DISJOINT;
    }


    private static List<String> getFiveTupleOfFlowRule(FlowRule flowRule) {
        List<String> result = new ArrayList<>();
        //获取IP五元组
        //获取协议类型，向下转化为具体的类
        //IP协议字段不能为空，否则下面无法判断TCP还是UDP 端口
        Criterion ipProtocol = flowRule.selector().getCriterion(Criterion.Type.IP_PROTO);
        StringBuffer stringBuffer = new StringBuffer();
        if (ipProtocol == null) {
            result.add("xxxxxxxx");
        } else {
            IPProtocolCriterion ipProtoCriterion = (IPProtocolCriterion) ipProtocol;
            //首先先添加 IP protocol number: 8 bits
            String ipProtocolString = Integer.toBinaryString(ipProtoCriterion.protocol());
            for (int i = 0; i < 8 - ipProtocolString.length(); i++) {
                stringBuffer.append("0");
            }
            stringBuffer.append(ipProtocolString);
            result.add(stringBuffer.toString());
        }

        //这里的IP地址是 IP前缀
        Criterion ipSrc = flowRule.selector().getCriterion(Criterion.Type.IPV4_SRC);
        //添加原目IP 地址到 HeaderSpace
        if (ipSrc != null) {
            IPCriterion ipSrcCriterion = (IPCriterion) ipSrc;
            result.add(HeaderSpaceUtil.ipToHeaderSpace(ipSrcCriterion));
        } else {
            result.add("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        }

        Criterion ipDst = flowRule.selector().getCriterion(Criterion.Type.IPV4_DST);
        if (ipDst != null) {
            IPCriterion ipDstCriterion = (IPCriterion) ipDst;
            result.add(HeaderSpaceUtil.ipToHeaderSpace(ipDstCriterion));
        } else {
            result.add("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        }


        Criterion tcpSrcPort = flowRule.selector().getCriterion(Criterion.Type.TCP_SRC);
        Criterion tcpDstPort = flowRule.selector().getCriterion(Criterion.Type.TCP_DST);
        Criterion tcpSrcPortMask = flowRule.selector().getCriterion(Criterion.Type.TCP_SRC_MASKED);
        Criterion tcpDstPortMask = flowRule.selector().getCriterion(Criterion.Type.TCP_DST_MASKED);


        if (tcpSrcPort != null) {
            TcpPortCriterion tcpPortCriterion = (TcpPortCriterion) tcpSrcPort;
            result.add(HeaderSpaceUtil.tcpPortToHeaderSpace(tcpPortCriterion));
        } else if (tcpSrcPort == null && tcpSrcPortMask != null) {
            TcpPortCriterion tcpPortCriterion = (TcpPortCriterion) tcpSrcPortMask;
            result.add(HeaderSpaceUtil.tcpPortToHeaderSpace(tcpPortCriterion));
        } else {
            result.add("xxxxxxxxxxxxxxxx");
        }
        if (tcpDstPort != null) {
            TcpPortCriterion tcpPortCriterion = (TcpPortCriterion) tcpSrcPort;
            result.add(HeaderSpaceUtil.tcpPortToHeaderSpace(tcpPortCriterion));
        } else if (tcpDstPort == null && tcpDstPortMask != null) {
            TcpPortCriterion tcpPortCriterion = (TcpPortCriterion) tcpDstPortMask;
            result.add(HeaderSpaceUtil.tcpPortToHeaderSpace(tcpPortCriterion));
        } else {
            result.add("xxxxxxxxxxxxxxxx");
        }

        Criterion udpSrcPort = flowRule.selector().getCriterion(Criterion.Type.UDP_SRC);
        Criterion udpDstPort = flowRule.selector().getCriterion(Criterion.Type.UDP_DST);
        Criterion udpSrcPortMask = flowRule.selector().getCriterion(Criterion.Type.UDP_SRC_MASKED);
        Criterion udpDstPortMask = flowRule.selector().getCriterion(Criterion.Type.UDP_DST_MASKED);

        if (udpSrcPort != null) {
            UdpPortCriterion udpPortCriterion = (UdpPortCriterion) udpSrcPort;
            result.add(HeaderSpaceUtil.udpPortToHeaderSpace(udpPortCriterion));
        } else if (udpSrcPort == null && (udpSrcPortMask != null)) {
            UdpPortCriterion udpPortCriterion = (UdpPortCriterion) udpSrcPortMask;
            result.add(HeaderSpaceUtil.udpPortToHeaderSpace(udpPortCriterion));
        } else {
            result.add("xxxxxxxxxxxxxxxx");
        }

        if (udpDstPort != null) {
            UdpPortCriterion udpPortCriterion = (UdpPortCriterion) udpDstPort;
            result.add(HeaderSpaceUtil.udpPortToHeaderSpace(udpPortCriterion));
        } else if (udpDstPort == null && udpDstPortMask != null) {
            UdpPortCriterion udpPortCriterion = (UdpPortCriterion) udpDstPortMask;
            result.add(HeaderSpaceUtil.udpPortToHeaderSpace(udpPortCriterion));
        } else {
            result.add("xxxxxxxxxxxxxxxx");
        }

        return result;
    }


    //处理 output,group，meter指令
    public static boolean instructionConflictCheckOld(FlowRule rxFlowRule, FlowRule ryFlowRule) {

        TrafficTreatment rxIns = rxFlowRule.treatment();
        TrafficTreatment ryIns = ryFlowRule.treatment();

        Instructions.OutputInstruction rxOutput = null;
        Instructions.OutputInstruction ryOutput = null;
        Instructions.GroupInstruction rxGroup = null;
        Instructions.GroupInstruction ryGroup = null;
        Instructions.NoActionInstruction rxNoAction = null;
        Instructions.NoActionInstruction ryNoAction = null;
        //meter指令用来进行QoS,与转发冲突无关
        Instructions.MeterInstruction rxMeter = null;
        Instructions.MeterInstruction ryMeter = null;

        for (Instruction instruction : rxIns.allInstructions()) {
            if (instruction instanceof Instructions.OutputInstruction) {
                rxOutput = (Instructions.OutputInstruction) instruction;
            } else if (instruction instanceof Instructions.GroupInstruction) {
                rxGroup = (Instructions.GroupInstruction) instruction;
            } else if (instruction instanceof Instructions.NoActionInstruction) {
                rxNoAction = (Instructions.NoActionInstruction) instruction;
            } else if (instruction instanceof Instructions.MeterInstruction) {
                rxMeter = (Instructions.MeterInstruction) instruction;
            }
        }
        for (Instruction instruction : ryIns.allInstructions()) {
            if (instruction instanceof Instructions.OutputInstruction) {
                ryOutput = (Instructions.OutputInstruction) instruction;
            } else if (instruction instanceof Instructions.GroupInstruction) {
                ryGroup = (Instructions.GroupInstruction) instruction;
            } else if (instruction instanceof Instructions.NoActionInstruction) {
                ryNoAction = (Instructions.NoActionInstruction) instruction;
            } else if (instruction instanceof Instructions.MeterInstruction) {
                ryMeter = (Instructions.MeterInstruction) instruction;
            }
        }
        if (rxOutput != null && ryOutput != null) {
            if (rxOutput.port().equals(ryOutput.port())) {
                return false;
            } else {
                return true;
            }
        } else if (rxGroup != null && ryGroup != null) {
            if (rxGroup.groupId().equals(ryGroup.groupId())) {
                return false;
            } else {
                return true;
            }
        } else if (rxMeter != null && ryMeter != null) {
            if (rxMeter.meterId().equals(ryMeter.meterId())) {
                return false;
            } else {
                return true;
            }
        } else if (rxNoAction != null && ryNoAction != null) {
            return false;
        } else {
            return true;
        }

    }

    //处理 output,group,goto-table，meter指令
    public static boolean instructionConflictCheck(FlowRule rxFlowRule, FlowRule ryFlowRule) {

        TrafficTreatment rxIns = rxFlowRule.treatment();
        TrafficTreatment ryIns = ryFlowRule.treatment();

        Instructions.OutputInstruction rxOutput = null;
        Instructions.OutputInstruction ryOutput = null;
        Instructions.GroupInstruction rxGroup = null;
        Instructions.GroupInstruction ryGroup = null;
        Instructions.NoActionInstruction rxNoAction = null;
        Instructions.NoActionInstruction ryNoAction = null;
        Instructions.TableTypeTransition rxTable = null;
        Instructions.TableTypeTransition ryTable = null;

        for (Instruction instruction : rxIns.allInstructions()) {
            if (instruction instanceof Instructions.OutputInstruction) {
                rxOutput = (Instructions.OutputInstruction) instruction;
            } else if (instruction instanceof Instructions.GroupInstruction) {
                rxGroup = (Instructions.GroupInstruction) instruction;
            } else if (instruction instanceof Instructions.NoActionInstruction) {
                rxNoAction = (Instructions.NoActionInstruction) instruction;
            } else if (instruction instanceof Instructions.TableTypeTransition) {
                rxTable = (Instructions.TableTypeTransition) instruction;
            }
        }
        for (Instruction instruction : ryIns.allInstructions()) {
            if (instruction instanceof Instructions.OutputInstruction) {
                ryOutput = (Instructions.OutputInstruction) instruction;
            } else if (instruction instanceof Instructions.GroupInstruction) {
                ryGroup = (Instructions.GroupInstruction) instruction;
            } else if (instruction instanceof Instructions.NoActionInstruction) {
                ryNoAction = (Instructions.NoActionInstruction) instruction;
            } else if (instruction instanceof Instructions.TableTypeTransition) {
                ryTable = (Instructions.TableTypeTransition) instruction;
            }
        }
        if (rxTable != null && ryTable != null) {
            if (rxTable.tableId().equals(ryTable.tableId())) {
                return false;
            } else {
                return true;
            }
        } else if (rxGroup != null && ryGroup != null) {
            if (rxGroup.groupId().equals(ryGroup.groupId())) {
                return false;
            } else {
                return true;
            }
        } else if (rxOutput != null && ryOutput != null) {
            if (rxOutput.port().equals(ryOutput.port())) {
                return false;
            } else {
                return true;
            }
        } else if (rxNoAction != null && ryNoAction != null) {
            return false;
        } else
            return true;


    }

}
