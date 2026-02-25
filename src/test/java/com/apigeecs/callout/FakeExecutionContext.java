package com.apigeecs.callout;

import com.apigee.flow.Fault;
import com.apigee.flow.execution.Callback;
import com.apigee.flow.execution.ExecutionContext;
import org.slf4j.Marker;

import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

/**
 * Minimal test stub for {@link ExecutionContext}.
 */
public class FakeExecutionContext implements ExecutionContext {

    @Override public Marker getMarker() { return null; }
    @Override public boolean isRequestFlow() { return true; }
    @Override public boolean isErrorFlow() { return false; }
    @Override public void submitTask(Runnable r) {}
    @Override public void submitTask(Runnable r, Callback cb, Object o) {}
    @Override public void scheduleTask(Runnable r, long delay, TimeUnit unit) {}
    @Override public void resume() {}
    @Override public void resume(Fault f) {}
    @Override public Collection<Fault> getFaults() { return Collections.emptyList(); }
    @Override public Fault getFault() { return null; }
    @Override public void addFault(Fault f) {}
}
