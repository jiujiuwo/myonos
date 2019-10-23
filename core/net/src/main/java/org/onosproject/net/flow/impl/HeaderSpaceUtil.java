package org.onosproject.net.flow.impl;

import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;
import org.onosproject.net.flow.criteria.UdpPortCriterion;

public class HeaderSpaceUtil {
    //将 IP Criterion转换为HeaderSpace
    public static String ipToHeaderSpace(IPCriterion ipCriterion) {
        StringBuffer result = new StringBuffer();

        //根据IPCriterion 拿到IP的byte数组和prefix
        byte[] ipSrcBytes = ipCriterion.ip().address().toOctets();
        int ipSrcPrefixLength = ipCriterion.ip().prefixLength();

        for (byte b : ipSrcBytes) {
            String tmpString = Integer.toBinaryString(b);
            for (int i = 0; i < 8 - tmpString.length(); i++) {
                result.append("0");
            }
            result.append(tmpString);
        }
        StringBuilder xxx = new StringBuilder();
        for (int i = 0; i < 4 * 8 - ipSrcPrefixLength; i++) {
            xxx.append("x");
        }
        //根据ipPrefix将末尾几位置x
        result.replace(result.length() - (4 * 8 - ipSrcPrefixLength), result.length(), xxx.toString());

        return result.toString();
    }

    //将TCP Port Criterion 转换为HeaderSpace
    public static String tcpPortToHeaderSpace(TcpPortCriterion tcpPortCriterion) {
        StringBuilder result = new StringBuilder();
        //tcp port 16 bit
        if (tcpPortCriterion.type().equals(Criterion.Type.TCP_SRC) ||
                tcpPortCriterion.type().equals(Criterion.Type.TCP_DST)) {
            String tcpPortString = Integer.toBinaryString(tcpPortCriterion.tcpPort().toInt());
            for (int i = 0; i < 16 - tcpPortString.length(); i++) {
                result.append("0");
            }
            result.append(tcpPortString);
            return result.toString();
        } else if (tcpPortCriterion.type().equals(Criterion.Type.TCP_SRC_MASKED) ||
                tcpPortCriterion.type().equals(Criterion.Type.TCP_DST_MASKED)) {

            String tcpPortString = Integer.toBinaryString(tcpPortCriterion.tcpPort().toInt());
            int tcpPortMask = Integer.bitCount(tcpPortCriterion.mask().toInt());


            for (int i = 0; i < 16 - tcpPortString.length(); i++) {
                result.append("0");
            }
            result.append(tcpPortString);

            StringBuilder xxx = new StringBuilder();

            for (int i = 0; i < 16 - tcpPortMask; i++) {
                xxx.append("x");
            }

            result.replace(16 - tcpPortMask, result.length(), xxx.toString());

            return result.toString();
        } else {
            result.append("xxxxxxxxxxxxxxxx");
            return result.toString();
        }
    }

    //将UDP Port Criterion 转换为HeaderSpace
    public static String udpPortToHeaderSpace(UdpPortCriterion udpPortCriterion) {
        StringBuilder result = new StringBuilder();
        //udp port 16 bit
        if (udpPortCriterion.type().equals(Criterion.Type.TCP_SRC) ||
                udpPortCriterion.type().equals(Criterion.Type.UDP_DST)) {
            String tcpPortString = Integer.toBinaryString(udpPortCriterion.udpPort().toInt());
            for (int i = 0; i < 16 - tcpPortString.length(); i++) {
                result.append("0");
            }
            result.append(tcpPortString);
            return result.toString();
        } else if (udpPortCriterion.type().equals(Criterion.Type.UDP_SRC_MASKED) ||
                udpPortCriterion.type().equals(Criterion.Type.UDP_DST_MASKED)) {

            String udpPortString = Integer.toBinaryString(udpPortCriterion.udpPort().toInt());
            int udpPortMask = Integer.bitCount(udpPortCriterion.mask().toInt());

            for (int i = 0; i < 16 - udpPortString.length(); i++) {
                result.append("0");
            }
            result.append(udpPortString);

            StringBuilder xxx = new StringBuilder();

            for (int i = 0; i < 16 - udpPortMask; i++) {
                xxx.append("x");
            }

            result.replace(16 - udpPortMask, result.length(), xxx.toString());

            return result.toString();
        } else {
            result.append("xxxxxxxxxxxxxxxx");
            return result.toString();
        }
    }

    public static int headerSpaceUnion(String x, String y) {
        byte[] xBytes = hsStringToBytes(x);
        byte[] yBytes = hsStringToBytes(y);
        return headerSpaceConflictCheck(xBytes, yBytes);
    }


    public static byte[] hsStringToBytes(String hsString) {

        if (hsString.length() <= 0) {
            return null;
        }

        byte[] result = new byte[hsString.length()];
        for (int i = 0; i < hsString.length(); i++) {
            if (hsString.charAt(i) == '0') {
                result[i] = Byte.parseByte("01");
            } else if (hsString.charAt(i) == '1') {
                result[i] = Byte.parseByte("10");
            } else if (hsString.charAt(i) == 'x') {
                result[i] = Byte.parseByte("11");
            } else {
                result[i] = Byte.parseByte("00");
            }
        }
        return result;
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
}
