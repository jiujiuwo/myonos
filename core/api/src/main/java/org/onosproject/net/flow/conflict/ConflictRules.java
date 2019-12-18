package org.onosproject.net.flow.conflict;

import org.onosproject.net.flow.FlowRule;

public class ConflictRules {

    private HandlerType handlerType;
    private FlowRule tmpRule;
    private FlowRule flowRule;

    public ConflictRules() {
    }

    public ConflictRules(FlowRule tmpRule, FlowRule flowRule, HandlerType handlerType) {
        this.flowRule = flowRule;
        this.tmpRule = tmpRule;
        this.handlerType = handlerType;
    }

    public FlowRule getTmpRule() {
        return tmpRule;
    }

    public void setTmpRule(FlowRule tmpRule) {
        this.tmpRule = tmpRule;
    }

    public FlowRule getFlowRule() {
        return flowRule;
    }

    public void setFlowRule(FlowRule flowRule) {
        this.flowRule = flowRule;
    }

    public HandlerType getHandlerType() {
        return handlerType;
    }

    public void setHandlerType(HandlerType handlerType) {
        this.handlerType = handlerType;
    }
}
