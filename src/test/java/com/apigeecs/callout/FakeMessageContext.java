package com.apigeecs.callout;

import com.apigee.flow.FlowInfo;
import com.apigee.flow.message.Connection;
import com.apigee.flow.message.FlowContext;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import com.apigee.flow.message.TransportMessage;

import java.util.HashMap;
import java.util.Map;

/**
 * Minimal test stub for {@link MessageContext} that stores flow variables in a HashMap.
 */
public class FakeMessageContext implements MessageContext {

    private final Map<String, Object> variables = new HashMap<>();

    public Map<String, Object> getVariables() {
        return variables;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getVariable(String name) {
        return (T) variables.get(name);
    }

    @Override
    public boolean setVariable(String name, Object value) {
        variables.put(name, value);
        return true;
    }

    @Override
    public boolean removeVariable(String name) {
        variables.remove(name);
        return true;
    }

    // DataProvider
    @Override
    @SuppressWarnings("unchecked")
    public <T extends Comparable> T get(String name) {
        Object val = variables.get(name);
        return (T) val;
    }

    // --- Unused stubs ---
    @Override public Message getMessage(FlowContext fc) { return null; }
    @Override public void setMessage(FlowContext fc, Message m) {}
    @Override public Message getRequestMessage() { return null; }
    @Override public void setRequestMessage(Message m) {}
    @Override public Message getResponseMessage() { return null; }
    @Override public void setResponseMessage(Message m) {}
    @Override public Message getErrorMessage() { return null; }
    @Override public void setErrorMessage(Message m) {}
    @Override public Message getMessage() { return null; }
    @Override public Connection getClientConnection() { return null; }
    @Override public Connection getTargetConnection() { return null; }
    @Override public <T extends FlowInfo> T getFlowInfo(String s) { return null; }
    @Override public boolean addFlowInfo(FlowInfo fi) { return false; }
    @Override public void removeFlowInfo(String s) {}
    @Override public Message createMessage(TransportMessage tm) { return null; }
}
