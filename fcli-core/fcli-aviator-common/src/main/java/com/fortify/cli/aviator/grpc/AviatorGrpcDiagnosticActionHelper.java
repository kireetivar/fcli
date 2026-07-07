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
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fortify.cli.aviator.grpc.AviatorGrpcDiagnosticReport.DiagnosticStatus;
import com.fortify.cli.aviator.grpc.AviatorGrpcDiagnosticReport.StepName;

final class AviatorGrpcDiagnosticActionHelper {
    private static final String FIELD_ADDITIONAL_RECOMMENDED_ACTIONS = "additionalRecommendedActions";
    private static final String FIELD_HINT = "hint";
    private static final String FIELD_RECOMMENDED_ACTION = "recommendedAction";
    private static final String FIELD_STATUS = "status";
    private static final String FIELD_STEP = "step";
    private static final String FIELD_SUMMARY = "summary";
    private static final String FIELD_TRUSTSTORE_SOURCE = "trustStoreSource";
    private static final String TRUSTSTORE_SOURCE_NONE = "none";
    private static final String ACTION_VERIFY_ACTIVE_TRUSTSTORE =
        "Verify the configured truststore contains the CA chain required by the Aviator gRPC endpoint";
    private static final String SUMMARY_ACTIVE_TRUSTSTORE_CONTEXT =
        "; a configured truststore is also active, so verify it if VPN, proxy, firewall, or load balancer checks pass";

    private AviatorGrpcDiagnosticActionHelper() {}

    static void addTrustStoreContextIfApplicable(ObjectNode step, ObjectNode environmentStep) {
        if ( !isFailedGrpcChannelStep(step) || !hasActiveTrustStore(environmentStep) ) {
            return;
        }
        if ( addAdditionalRecommendedAction(step, ACTION_VERIFY_ACTIVE_TRUSTSTORE) ) {
            step.put(FIELD_SUMMARY, step.path(FIELD_SUMMARY).asText() + SUMMARY_ACTIVE_TRUSTSTORE_CONTEXT);
            step.put(FIELD_HINT, buildHint(step));
        }
    }

    private static boolean addAdditionalRecommendedAction(ObjectNode step, String action) {
        if ( StringUtils.isBlank(action) || hasAdditionalRecommendedAction(step, action) ) {
            return false;
        }
        step.withArray(FIELD_ADDITIONAL_RECOMMENDED_ACTIONS).add(action);
        return true;
    }

    private static boolean hasAdditionalRecommendedAction(ObjectNode step, String action) {
        for ( JsonNode actionNode : step.withArray(FIELD_ADDITIONAL_RECOMMENDED_ACTIONS) ) {
            if ( action.equals(actionNode.asText()) ) {
                return true;
            }
        }
        return false;
    }

    private static String buildHint(ObjectNode step) {
        List<String> actions = new ArrayList<>();
        String recommendedAction = step.path(FIELD_RECOMMENDED_ACTION).asText();
        if ( StringUtils.isNotBlank(recommendedAction) ) {
            actions.add(recommendedAction);
        }
        for ( JsonNode actionNode : step.withArray(FIELD_ADDITIONAL_RECOMMENDED_ACTIONS) ) {
            actions.add(actionNode.asText());
        }
        return String.join("; ", actions);
    }

    private static boolean isFailedGrpcChannelStep(ObjectNode step) {
        return step != null
                && StepName.GRPC_CHANNEL.text().equals(step.path(FIELD_STEP).asText())
                && DiagnosticStatus.FAILED.name().equals(step.path(FIELD_STATUS).asText());
    }

    private static boolean hasActiveTrustStore(ObjectNode environmentStep) {
        if ( environmentStep == null ) {
            return false;
        }
        String trustStoreSource = environmentStep.path(FIELD_TRUSTSTORE_SOURCE).asText(TRUSTSTORE_SOURCE_NONE);
        return StringUtils.isNotBlank(trustStoreSource) && !TRUSTSTORE_SOURCE_NONE.equalsIgnoreCase(trustStoreSource);
    }
}