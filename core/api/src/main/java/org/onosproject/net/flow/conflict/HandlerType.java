package org.onosproject.net.flow.conflict;

public enum HandlerType {
    Reject(0), Install(1), RemoveAndInstall(2), DecreasePriorityAndInstall(3);

    private int handlerType;

    private HandlerType(int type) {
        this.handlerType = type;
    }



}
