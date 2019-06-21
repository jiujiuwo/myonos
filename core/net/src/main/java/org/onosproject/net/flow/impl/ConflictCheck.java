package org.onosproject.net.flow.impl;

import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPProtocolCriterion;

public class ConflictCheck {

    //后续使用 heapByteBuffer 试试
    public static boolean headerSpaceConflictCheck(byte[] hs1,byte[] hs2){
        if(hs1.length!=hs2.length){
            System.out.println("error");
            return true;
        }

        for(int i=0;i<hs1.length;i++){
            byte tmp = (byte)(hs1[i]&hs2[i]);
            if(tmp==00){
                return false;
            }
        }
        return true;
    }

    public static boolean filedRangeConflictCheck(FlowRule tmpRule,FlowRule Rx){

        //获取IP五元组
        Criterion ipProtocol = tmpRule.selector().getCriterion(Criterion.Type.IP_PROTO);
        IPProtocolCriterion ipProtoCriterion = (IPProtocolCriterion)ipProtocol;

        //这里的IP地址是 IP前缀
        Criterion ipSrc = tmpRule.selector().getCriterion(Criterion.Type.IPV4_SRC);
        Criterion ipDst =tmpRule.selector().getCriterion(Criterion.Type.IPV4_DST);

        if(ipProtoCriterion.protocol()==6){ //TCP = 6
            Criterion tcpSrcPort = tmpRule.selector().getCriterion(Criterion.Type.TCP_SRC);
            Criterion tcpDstPort = tmpRule.selector().getCriterion(Criterion.Type.TCP_DST);
            Criterion tcpSrcPortMask = tmpRule.selector().getCriterion(Criterion.Type.TCP_SRC_MASKED);
            Criterion tcpDstPortMask = tmpRule.selector().getCriterion(Criterion.Type.TCP_DST_MASKED);
        }else if(ipProtoCriterion.protocol()==17){ //UDP = 17
            Criterion udpSrcPort = tmpRule.selector().getCriterion(Criterion.Type.UDP_SRC);
            Criterion udpDstPort = tmpRule.selector().getCriterion(Criterion.Type.UDP_DST);
            Criterion udpSrcPortMask = tmpRule.selector().getCriterion(Criterion.Type.UDP_SRC_MASKED);
            Criterion udpDstPortMask = tmpRule.selector().getCriterion(Criterion.Type.UDP_DST_MASKED);
        }

        return false;
    }

}
