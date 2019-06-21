package org.onosproject.net.flow.impl;

import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.criteria.Criterion;

import java.util.ArrayList;
import java.util.List;

public class ConflictCheck {

    /*
        如果交集为空，则返回0
        如果交集非空，部分相交返回1，包含关系返回2
     */
    public static int headerSpaceConflictCheck(byte[] rxBytes, byte[] ryBytes) {
        if (rxBytes.length != ryBytes.length) {
            System.out.println("error");
            return 0;
        }
        boolean sameWithRx = true;
        boolean sameWithRy = true;
        for (int i = 0; i < rxBytes.length; i++) {
            byte tmp = (byte) (rxBytes[i] & ryBytes[i]);
            if (tmp == 00) {
                return 0;
            }
            if (tmp != rxBytes[i]) {
                sameWithRx = false;
            }
            if (tmp != ryBytes[i]) {
                sameWithRy = false;
            }
        }

        if (sameWithRx || sameWithRy) {
            return 2;
        } else {
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

}
