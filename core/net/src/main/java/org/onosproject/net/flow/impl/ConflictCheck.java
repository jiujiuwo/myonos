package org.onosproject.net.flow.impl;

import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;

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

    /*
        如果交集为空，则返回0
        如果交集非空，部分相交返回1，Rx包含Ry返回2，Ry包含Rx返回3
     */
    public static int headerSpaceConflictCheck(byte[] rxBytes, byte[] ryBytes) {
        if (rxBytes.length != ryBytes.length) {
            // System.out.println("error");
            return 0;
        }
        boolean sameWithRx = true;
        boolean sameWithRy = true;
        for (int i = 0; i < rxBytes.length; i++) {
            byte tmp = (byte) (rxBytes[i] & ryBytes[i]);
            if (tmp == 0) {
                return 0;
            }
            if (tmp != rxBytes[i]) {
                sameWithRx = false;
            }
            if (tmp != ryBytes[i]) {
                sameWithRy = false;
            }
        }

        if (sameWithRx) {
            return 2;
        } else if (sameWithRy) {
            return 3;
        } else {
            return 1;
        }
    }


    /*  基于字段范围的检测方法
        如果交集为空，则返回0
        如果交集非空，部分相交返回1，Rx包含Ry返回2，Ry包含Rx返回3
     */
    public static anomals filedRangeConflictCheck(FlowRule rxFlowRule, FlowRule ryFLowRule) {

        relations relation = relations.UNKNOWN;//0 unknown,1 exact, 2 subset,3 superset, 4 intersectant

        List<String> rxList = getFiveTupleOfFlowRule(rxFlowRule);
        List<String> ryList = getFiveTupleOfFlowRule(ryFLowRule);

        for (int i = 0; i < rxList.size(); i++) {
            if (rxList.get(i).equals(ryList.get(i))) {
                if (relation == relations.UNKNOWN) {
                    relation = relations.EXACT;
                }
            } else if (isSubset(rxList.get(i), ryList.get(i))) {
                if (relation == relations.SUBSET || relation == relations.CORRELATED) {
                    relation = relation.CORRELATED;
                } else {
                    relation = relations.SUPERSET;
                }
            } else if (isSubset(ryList.get(i), rxList.get(i))) {
                if (relation == relations.SUPERSET || relation == relations.CORRELATED) {
                    relation = relations.CORRELATED;
                } else {
                    relation = relations.SUBSET;
                }
            } else {
                return anomals.DISJOINT;
            }
        }

        boolean insCon = instructionConflictCheck(rxFlowRule, ryFLowRule);
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

    private static boolean isSubset(String x, String y) {
        System.out.println(x + " " + y);
        return false;
    }

    /*
        index 0 协议类型
        index 1 原IP地址
        index 2 目的IP地址
        index 3 TCP 原端口号
        index 4 TCP 目的端口号
        index 5 UDP 原端口号
        index 6 UDP目的端口号
     */
    private static List<String> getFiveTupleOfFlowRule(FlowRule flowRule) {
        List<String> result = new ArrayList<>();
        //获取IP五元组
        Criterion ipProtocol = flowRule.selector().getCriterion(Criterion.Type.IP_PROTO);

        if (ipProtocol != null) {
            result.add(ipProtocol.toString());
        } else {
            result.add("*");
        }

        //这里的IP地址是 IP前缀
        Criterion ipSrc = flowRule.selector().getCriterion(Criterion.Type.IPV4_SRC);
        if (ipSrc != null) {
            result.add(ipSrc.toString());
        } else {
            result.add("*");
        }

        Criterion ipDst = flowRule.selector().getCriterion(Criterion.Type.IPV4_DST);
        if (ipDst != null) {
            result.add(ipDst.toString());
        } else {
            result.add("*");
        }


        Criterion tcpSrcPort = flowRule.selector().getCriterion(Criterion.Type.TCP_SRC);
        Criterion tcpDstPort = flowRule.selector().getCriterion(Criterion.Type.TCP_DST);
        Criterion tcpSrcPortMask = flowRule.selector().getCriterion(Criterion.Type.TCP_SRC_MASKED);
        Criterion tcpDstPortMask = flowRule.selector().getCriterion(Criterion.Type.TCP_DST_MASKED);
        Criterion udpSrcPort = flowRule.selector().getCriterion(Criterion.Type.UDP_SRC);
        Criterion udpDstPort = flowRule.selector().getCriterion(Criterion.Type.UDP_DST);
        Criterion udpSrcPortMask = flowRule.selector().getCriterion(Criterion.Type.UDP_SRC_MASKED);
        Criterion udpDstPortMask = flowRule.selector().getCriterion(Criterion.Type.UDP_DST_MASKED);

        if (tcpSrcPort != null) {
            result.add(tcpSrcPort.toString());
        } else if (tcpSrcPort == null && tcpSrcPortMask != null) {
            result.add(tcpDstPortMask.toString());
        } else {
            result.add("*");
        }

        if (tcpDstPort != null) {
            result.add(tcpDstPort.toString());
        } else if (tcpDstPort == null && tcpDstPortMask != null) {
            result.add(tcpDstPortMask.toString());
        } else {
            result.add("*");
        }

        if (udpSrcPort != null) {
            result.add(udpSrcPort.toString());
        } else if (udpSrcPort == null && udpSrcPortMask != null) {
            result.add(udpDstPortMask.toString());
        } else {
            result.add("*");
        }

        if (udpDstPort != null) {
            result.add(udpDstPort.toString());
        } else if (udpDstPort == null && udpDstPortMask != null) {
            result.add(udpDstPortMask.toString());
        } else {
            result.add("*");
        }
        return result;
    }

    private static void getCheckInstructions(TrafficTreatment treatment, Instructions.OutputInstruction outputInstruction,
                                             Instructions.GroupInstruction groupInstruction, Instructions.NoActionInstruction
                                                     noActionInstruction, Instructions.TableTypeTransition tableTypeTransition) {

        for (Instruction instruction : treatment.allInstructions()) {
            if (instruction instanceof Instructions.OutputInstruction) {
                outputInstruction = (Instructions.OutputInstruction) instruction;
            } else if (instruction instanceof Instructions.GroupInstruction) {
                groupInstruction = (Instructions.GroupInstruction) instruction;
            } else if (instruction instanceof Instructions.NoActionInstruction) {
                noActionInstruction = (Instructions.NoActionInstruction) instruction;
            } else if (instruction instanceof Instructions.TableTypeTransition) {
                tableTypeTransition = (Instructions.TableTypeTransition) instruction;
            }
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

        getCheckInstructions(rxIns, rxOutput, rxGroup, rxNoAction, rxTable);
        getCheckInstructions(ryIns, ryOutput, ryGroup, ryNoAction, ryTable);

        if (rxOutput != null && ryOutput != null) {
            if (rxOutput.port().equals(rxOutput.port())) {
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
        } else if (rxNoAction != null && ryNoAction != null) {
            return false;
        } else if (rxTable != null && ryTable != null) {
            if (rxTable.tableId().equals(ryTable.tableId())) {
                return false;
            } else {
                return true;
            }
        } else {
            return false;
        }

    }

}
