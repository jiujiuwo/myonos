package org.onosproject.net.flow.impl;

import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPProtocolCriterion;

public class ConflictCheck {

    /*
        如果交集为空，则返回0
        如果交集非空，部分相交返回1，包含关系返回2
     */
    public static int headerSpaceConflictCheck(byte[] rxBytes,byte[] ryBytes){
        if(rxBytes.length!=ryBytes.length){
            System.out.println("error");
            return 0;
        }
        boolean sameWithRx = true;
        boolean sameWithRy = true;
        for(int i=0;i<rxBytes.length;i++){
            byte tmp = (byte)(rxBytes[i]&ryBytes[i]);
            if(tmp==00){
                return 0;
            }
            if(tmp!=rxBytes[i]){
                sameWithRx = false;
            }
            if(tmp!=ryBytes[i]){
                sameWithRy = false;
            }
        }

        if(sameWithRx||sameWithRy){
            return 2;
        }else {
            return 1;
        }
    }

    public static int filedRangeConflictCheck(FlowRule rxFlowRule,FlowRule ryFLowRule){

        //获取IP五元组
        Criterion ipProtocol = rxFlowRule.selector().getCriterion(Criterion.Type.IP_PROTO);
        IPProtocolCriterion ipProtoCriterion = (IPProtocolCriterion)ipProtocol;

        //这里的IP地址是 IP前缀
        Criterion ipSrc = rxFlowRule.selector().getCriterion(Criterion.Type.IPV4_SRC);
        Criterion ipDst =rxFlowRule.selector().getCriterion(Criterion.Type.IPV4_DST);

        if(ipProtoCriterion.protocol()==6){ //TCP = 6
            Criterion tcpSrcPort = rxFlowRule.selector().getCriterion(Criterion.Type.TCP_SRC);
            Criterion tcpDstPort = rxFlowRule.selector().getCriterion(Criterion.Type.TCP_DST);
            Criterion tcpSrcPortMask = rxFlowRule.selector().getCriterion(Criterion.Type.TCP_SRC_MASKED);
            Criterion tcpDstPortMask = rxFlowRule.selector().getCriterion(Criterion.Type.TCP_DST_MASKED);
        }else if(ipProtoCriterion.protocol()==17){ //UDP = 17
            Criterion udpSrcPort = rxFlowRule.selector().getCriterion(Criterion.Type.UDP_SRC);
            Criterion udpDstPort = rxFlowRule.selector().getCriterion(Criterion.Type.UDP_DST);
            Criterion udpSrcPortMask = rxFlowRule.selector().getCriterion(Criterion.Type.UDP_SRC_MASKED);
            Criterion udpDstPortMask = rxFlowRule.selector().getCriterion(Criterion.Type.UDP_DST_MASKED);
        }

        return 0;
    }

}
