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

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

public record AviatorGrpcDiagnosticReport(ArrayNode steps, boolean connectivityFailure) {
    private static final String FIELD_ADDITIONAL_RECOMMENDED_ACTIONS = "additionalRecommendedActions";
    private static final String FIELD_FAILURE_CATEGORY = "failureCategory";
    private static final String FIELD_RECOMMENDED_ACTION = "recommendedAction";
    private static final String FIELD_STATUS = "status";
    private static final String FIELD_SUMMARY = "summary";

    public ArrayNode toJson() {
        return steps;
    }

    public AviatorGrpcDiagnosticVerdict verdict() {
        JsonNode firstFailure = findFirstStep(DiagnosticStatus.FAILED);
        if ( firstFailure != null ) {
            boolean stepConnectivityFailure = AviatorGrpcConnectivityDiagnosticHelper.isConnectivityFailureStep(firstFailure);
            return AviatorGrpcDiagnosticVerdict.failure(
                    stepConnectivityFailure ? "Connectivity failed" : "Diagnostic failed after reaching the service",
                    firstFailure.path("step").asText(),
                    firstFailure.path(FIELD_FAILURE_CATEGORY).asText(null),
                    firstFailure.path(FIELD_SUMMARY).asText(),
                    firstFailure.path(FIELD_RECOMMENDED_ACTION).asText(null),
                    getAdditionalRecommendedActions(firstFailure),
                    connectivityFailure);
        }

        JsonNode firstWarning = findFirstStep(DiagnosticStatus.WARN);
        if ( firstWarning != null ) {
            return AviatorGrpcDiagnosticVerdict.warning(
                    "Connectivity completed with warnings",
                    firstWarning.path("step").asText(),
                    firstWarning.path(FIELD_FAILURE_CATEGORY).asText(null),
                    firstWarning.path(FIELD_SUMMARY).asText(),
                    firstWarning.path(FIELD_RECOMMENDED_ACTION).asText(null),
                    getAdditionalRecommendedActions(firstWarning));
        }

        return AviatorGrpcDiagnosticVerdict.success("Connectivity OK: all required probes passed");
    }

    private JsonNode findFirstStep(DiagnosticStatus status) {
        for ( JsonNode step : steps ) {
            if ( status.name().equals(step.path(FIELD_STATUS).asText()) ) {
                return step;
            }
        }
        return null;
    }

    private static List<String> getAdditionalRecommendedActions(JsonNode step) {
        List<String> actions = new ArrayList<>();
        for ( JsonNode actionNode : step.path(FIELD_ADDITIONAL_RECOMMENDED_ACTIONS) ) {
            String action = actionNode.asText();
            if ( StringUtils.isNotBlank(action) ) {
                actions.add(action);
            }
        }
        return actions;
    }

    public enum DiagnosticStatus {
        OK,
        WARN,
        FAILED,
        SKIPPED;

        public static DiagnosticStatus fromText(String value) {
            if ( value == null ) {
                return null;
            }
            for ( DiagnosticStatus status : values() ) {
                if ( status.name().equals(value) ) {
                    return status;
                }
            }
            return null;
        }
    }

    enum StepName {
        TARGET("target", false),
        ENVIRONMENT("environment", false),
        DNS("dns", true),
        TCP("tcp", true),
        TLS_ALPN("tls-alpn", true),
        GRPC_CHANNEL("grpc-channel", true),
        GRPC_RESPONSE("grpc-response", true);

        private final String text;
        private final boolean connectivityStep;

        StepName(String text, boolean connectivityStep) {
            this.text = text;
            this.connectivityStep = connectivityStep;
        }

        String text() {
            return text;
        }

        boolean isConnectivityStep() {
            return connectivityStep;
        }

        static StepName fromText(String value) {
            for ( StepName stepName : values() ) {
                if ( stepName.text.equals(value) ) {
                    return stepName;
                }
            }
            return null;
        }
    }
}