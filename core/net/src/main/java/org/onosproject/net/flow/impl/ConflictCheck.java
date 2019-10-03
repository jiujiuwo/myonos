package org.onosproject.net.flow.impl;

import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;

import java.util.ArrayList;
import java.util.List;

public class ConflictCheck {

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

        if(sameWithRx){
            return 2;
        }else if(sameWithRy){
            return 3;
        }else{
            return 1;
        }
    }

    // 基于字段范围的检测方法
    public static int filedRangeConflictCheck(FlowRule rxFlowRule, FlowRule ryFLowRule) {

        List<String> rxList = getFiveTupleOfFlowRule(rxFlowRule);
        List<String> ryList = getFiveTupleOfFlowRule(ryFLowRule);

        for(int i=0;i<rxList.size();i++){

        }

        return 0;
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

        if(tcpSrcPort!=null){
            result.add(tcpSrcPort.toString());
        }else if(tcpSrcPort==null&&tcpSrcPortMask!=null){
            result.add(tcpDstPortMask.toString());
        }else{
            result.add("*");
        }

        if(tcpDstPort!=null){
            result.add(tcpDstPort.toString());
        }else if(tcpDstPort==null&&tcpDstPortMask!=null){
            result.add(tcpDstPortMask.toString());
        }else{
            result.add("*");
        }

        if(udpSrcPort!=null){
            result.add(udpSrcPort.toString());
        }else if(udpSrcPort==null&&udpSrcPortMask!=null){
            result.add(udpDstPortMask.toString());
        }else{
            result.add("*");
        }

        if(udpDstPort!=null){
            result.add(udpDstPort.toString());
        }else if(udpDstPort==null&&udpDstPortMask!=null){
            result.add(udpDstPortMask.toString());
        }else{
            result.add("*");
        }
        return result;
    }

    //处理 output,group,goto-table，meter指令
    public static boolean instructionConflictCheck(FlowRule rxFlowRule,FlowRule ryFlowRule){

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

        for(Instruction instruction:rxIns.allInstructions()){
            if(instruction instanceof Instructions.OutputInstruction){
                rxOutput = (Instructions.OutputInstruction)instruction;
            }else if(instruction instanceof Instructions.GroupInstruction){
                rxGroup = (Instructions.GroupInstruction)instruction;
            }else if(instruction instanceof  Instructions.NoActionInstruction){
                rxNoAction = (Instructions.NoActionInstruction)instruction;
            }else if(instruction instanceof Instructions.TableTypeTransition){
                rxTable = (Instructions.TableTypeTransition)instruction;
            }
        }


        for(Instruction instruction:ryIns.allInstructions()){
            if(instruction instanceof Instructions.OutputInstruction){
                ryOutput = (Instructions.OutputInstruction)instruction;
            }else if(instruction instanceof Instructions.GroupInstruction){
                ryGroup = (Instructions.GroupInstruction)instruction;
            }else if(instruction instanceof  Instructions.NoActionInstruction){
                ryNoAction = (Instructions.NoActionInstruction)instruction;
            }else if(instruction instanceof Instructions.TableTypeTransition){
                ryTable = (Instructions.TableTypeTransition)instruction;
            }
        }

        if(rxOutput!=null&&ryOutput!=null){
            if(rxOutput.port().equals(rxOutput.port())){
                return false;
            }else{
                return true;
            }
        }else if(rxGroup!=null&&ryGroup!=null){
            if(rxGroup.groupId().equals(ryGroup.groupId())){
                return false;
            }else{
                return true;
            }
        }else if(rxNoAction!=null&&ryNoAction!=null){
            return false;
        }else if(rxTable!=null&&ryTable!=null){
            if(rxTable.tableId().equals(ryTable.tableId())){
                return false;
            }
        }else{

        }

        return false;
    }

}
