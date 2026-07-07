/*
 * Copyright 2021-2026 Open Text.
 *
 * The only warranties for products and services of Open Text
 * and its affiliates and licensors ("Open Text") are as may
 * be set forth in the express warranty statements accompanying
 * such products and services. Nothing herein should be construed
 * as constituting an additional warranty. Open Text shall not be
 * liable for technical or editorial errors or omissions contained
 * herein. The information contained herein is subject to change
 * without notice.
 */
package com.fortify.cli.aviator.grpc;

import java.time.Duration;
import java.time.Instant;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fortify.cli.common.json.JsonHelper;

import io.grpc.ConnectivityState;
import lombok.extern.slf4j.Slf4j;

@Slf4j
final class GrpcChannelProbeState {
    private final ArrayNode stateTransitions = JsonHelper.getObjectMapper().createArrayNode();
    private ConnectivityState state;
    private int transientFailureCount;
    private int retryCyclesObserved;

    GrpcChannelProbeState(ConnectivityState initialState, Instant start) {
        this.state = initialState;
        observeState(null, initialState, start);
    }

    void transitionTo(ConnectivityState newState, Instant start) {
        ConnectivityState previousState = state;
        state = newState;
        if ( previousState == ConnectivityState.TRANSIENT_FAILURE && newState == ConnectivityState.CONNECTING ) {
            retryCyclesObserved++;
        }
        observeState(previousState, newState, start);
    }

    boolean isReady() {
        return state == ConnectivityState.READY;
    }

    boolean isShutdown() {
        return state == ConnectivityState.SHUTDOWN;
    }

    boolean sawTransientFailure() {
        return transientFailureCount > 0;
    }

    ConnectivityState state() {
        return state;
    }

    ArrayNode stateTransitions() {
        return stateTransitions;
    }

    int transientFailureCount() {
        return transientFailureCount;
    }

    int retryCyclesObserved() {
        return retryCyclesObserved;
    }

    private void observeState(ConnectivityState previousState, ConnectivityState observedState, Instant start) {
        if ( observedState == ConnectivityState.TRANSIENT_FAILURE && previousState != ConnectivityState.TRANSIENT_FAILURE ) {
            transientFailureCount++;
        }
        addStateTransition(observedState, start);
    }

    private void addStateTransition(ConnectivityState observedState, Instant start) {
        String stateName = observedState.name();
        if ( stateTransitions.size() > 0 && stateName.equals(stateTransitions.get(stateTransitions.size() - 1).path("state").asText()) ) {
            return;
        }
        var stateTransition = stateTransitions.addObject();
        stateTransition.put("state", stateName);
        long elapsedMs = Duration.between(start, Instant.now()).toMillis();
        stateTransition.put("elapsedMs", elapsedMs);
        log.debug("Aviator diagnose gRPC channel state={} elapsedMs={}", stateName, elapsedMs);
    }
}