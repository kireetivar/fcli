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

import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fortify.cli.common.json.JsonHelper;

public record AviatorGrpcDiagnosticVerdict(AviatorGrpcDiagnosticVerdict.Severity severity, String headline, String step,
        String failureCategory, String summary, String recommendedAction, List<String> additionalRecommendedActions,
        boolean connectivityFailure) {
    private static final String FIELD_ADDITIONAL_RECOMMENDED_ACTIONS = "additionalRecommendedActions";
    private static final String FIELD_FAILURE_CATEGORY = "failureCategory";
    private static final String FIELD_RECOMMENDED_ACTION = "recommendedAction";
    private static final String FIELD_SUMMARY = "summary";

    public AviatorGrpcDiagnosticVerdict {
        additionalRecommendedActions = additionalRecommendedActions == null ? List.of() : List.copyOf(additionalRecommendedActions);
    }

    static AviatorGrpcDiagnosticVerdict success(String headline) {
        return new AviatorGrpcDiagnosticVerdict(Severity.OK, headline, null, null, null, null, List.of(), false);
    }

    static AviatorGrpcDiagnosticVerdict warning(String headline, String step, String failureCategory, String summary,
            String recommendedAction, List<String> additionalRecommendedActions) {
        return new AviatorGrpcDiagnosticVerdict(Severity.WARN, headline, step, failureCategory, summary,
                recommendedAction, additionalRecommendedActions, false);
    }

    static AviatorGrpcDiagnosticVerdict failure(String headline, String step, String failureCategory, String summary,
            String recommendedAction, List<String> additionalRecommendedActions, boolean connectivityFailure) {
        return new AviatorGrpcDiagnosticVerdict(Severity.FAILED, headline, step, failureCategory, summary,
                recommendedAction, additionalRecommendedActions, connectivityFailure);
    }

    public String toDisplayString() {
        if ( severity == Severity.OK ) {
            return headline;
        }
        StringBuilder builder = new StringBuilder(headline);
        if ( StringUtils.isNotBlank(step) ) {
            builder.append(" - step '").append(step).append("'");
        }
        if ( StringUtils.isNotBlank(failureCategory) ) {
            builder.append(" reported ").append(failureCategory);
        }
        if ( StringUtils.isNotBlank(summary) ) {
            builder.append(": ").append(summary);
        }
        if ( StringUtils.isNotBlank(recommendedAction) ) {
            builder.append("; next action: ").append(recommendedAction);
        }
        if ( !additionalRecommendedActions.isEmpty() ) {
            builder.append("; also check: ").append(String.join("; ", additionalRecommendedActions));
        }
        return builder.toString();
    }

    public ObjectNode asJson() {
        ObjectNode result = JsonHelper.getObjectMapper().createObjectNode();
        result.put("severity", severity.name());
        result.put("headline", headline);
        result.put("display", toDisplayString());
        result.put("connectivityFailure", connectivityFailure);
        if ( StringUtils.isNotBlank(step) ) {
            result.put("step", step);
        }
        if ( StringUtils.isNotBlank(failureCategory) ) {
            result.put(FIELD_FAILURE_CATEGORY, failureCategory);
        }
        if ( StringUtils.isNotBlank(summary) ) {
            result.put(FIELD_SUMMARY, summary);
        }
        if ( StringUtils.isNotBlank(recommendedAction) ) {
            result.put(FIELD_RECOMMENDED_ACTION, recommendedAction);
        }
        if ( !additionalRecommendedActions.isEmpty() ) {
            ArrayNode actionsNode = result.putArray(FIELD_ADDITIONAL_RECOMMENDED_ACTIONS);
            additionalRecommendedActions.forEach(actionsNode::add);
        }
        return result;
    }

    public enum Severity {
        OK,
        WARN,
        FAILED
    }
}