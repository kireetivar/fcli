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
package com.fortify.cli.aviator.audit;

import java.util.Map;
import java.util.Set;

import com.fortify.cli.aviator.audit.model.SastAuditMode;
import com.fortify.cli.aviator.fpr.model.AuditIssue;
import com.fortify.cli.aviator.util.Constants;
import com.fortify.cli.aviator.util.StringUtil;

public final class SastAuditEligibility {
    private SastAuditEligibility() {}

    public enum Reason {
        ELIGIBLE_UNAUDITED,
        ELIGIBLE_AVIATOR_REAUDIT,
        ELIGIBLE_HUMAN_REAUDIT,
        EXCLUDED_SUPPRESSED,
        EXCLUDED_HUMAN_AUDIT,
        EXCLUDED_AVIATOR_AUDIT,
        EXCLUDED_ALREADY_AUDITED
    }

    public record Decision(boolean eligible, Reason reason) {}

    public static Decision evaluate(AuditIssue issue, SastAuditMode mode,
            Set<String> relevantTagIds, Set<String> analysisTagIds) {
        if (issue != null && issue.isSuppressed()) {
            return new Decision(false, Reason.EXCLUDED_SUPPRESSED);
        }

        boolean humanAudit = hasWriter(issue, relevantTagIds, false);
        boolean aviatorAudit = hasWriter(issue, relevantTagIds, true) || isProcessedByAviator(issue);
        if (mode == SastAuditMode.REAUDIT_AVIATOR_AND_HUMAN && humanAudit) {
            return new Decision(true, Reason.ELIGIBLE_HUMAN_REAUDIT);
        }
        if (mode == SastAuditMode.REAUDIT_AVIATOR && humanAudit) {
            return new Decision(false, Reason.EXCLUDED_HUMAN_AUDIT);
        }
        if (mode != SastAuditMode.UNAUDITED && aviatorAudit) {
            return new Decision(true, Reason.ELIGIBLE_AVIATOR_REAUDIT);
        }
        if (isNormallyAudited(issue, analysisTagIds)) {
            return new Decision(false, Reason.EXCLUDED_ALREADY_AUDITED);
        }
        if (mode == SastAuditMode.UNAUDITED && isProcessedByAviator(issue)) {
            return new Decision(false, Reason.EXCLUDED_AVIATOR_AUDIT);
        }
        return new Decision(true, Reason.ELIGIBLE_UNAUDITED);
    }

    private static boolean hasWriter(AuditIssue issue, Set<String> tagIds, boolean aviator) {
        if (issue == null || issue.getTags() == null || issue.getLastTagUsernames() == null) {
            return false;
        }
        Map<String, String> tags = issue.getTags();
        Map<String, String> usernames = issue.getLastTagUsernames();
        return tagIds.stream().anyMatch(tagId -> {
            String value = tags.get(tagId);
            String username = usernames.get(tagId);
            if (StringUtil.isPendingReviewValue(value) || StringUtil.isEmpty(username) || username.isBlank()) {
                return false;
            }
            return Constants.isAviatorAuditUsername(username) == aviator;
        });
    }

    private static boolean isProcessedByAviator(AuditIssue issue) {
        return issue != null && issue.getTags() != null
                && Constants.PROCESSED_BY_AVIATOR.equalsIgnoreCase(issue.getTags().get(Constants.AVIATOR_STATUS_TAG_ID));
    }

    private static boolean isNormallyAudited(AuditIssue issue, Set<String> analysisTagIds) {
        if (issue == null || issue.getTags() == null) {
            return false;
        }
        Map<String, String> tags = issue.getTags();
        if (!StringUtil.isPendingReviewValue(tags.get(Constants.AUDITOR_STATUS_TAG_ID))
                || tags.containsKey(Constants.AVIATOR_EXPECTED_OUTCOME_TAG_ID)
                || !StringUtil.isPendingReviewValue(tags.get(Constants.FOD_TAG_ID))) {
            return true;
        }
        return analysisTagIds.stream().anyMatch(tagId -> !StringUtil.isPendingReviewValue(tags.get(tagId)));
    }
}