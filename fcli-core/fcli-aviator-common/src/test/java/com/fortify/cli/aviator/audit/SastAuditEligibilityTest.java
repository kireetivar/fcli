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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.fortify.cli.aviator.audit.model.SastAuditMode;
import com.fortify.cli.aviator.fpr.model.AuditIssue;
import com.fortify.cli.aviator.util.Constants;

class SastAuditEligibilityTest {
    private static final Set<String> RELEVANT_TAGS = Set.of(
            Constants.ANALYSIS_TAG_ID, Constants.AUDITOR_STATUS_TAG_ID, Constants.FOD_TAG_ID);
    private static final Set<String> ANALYSIS_TAGS = Set.of(Constants.ANALYSIS_TAG_ID);

    @Test
    void humanAnalysisRemainsHumanWhenAviatorLaterWritesStatus() {
        AuditIssue issue = issue(
                Map.of(Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE,
                        Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR),
                Map.of(Constants.ANALYSIS_TAG_ID, "analyst.user",
                        Constants.AVIATOR_STATUS_TAG_ID, Constants.USER_NAME));

        var aviatorDecision = SastAuditEligibility.evaluate(
                issue, SastAuditMode.REAUDIT_AVIATOR, RELEVANT_TAGS, ANALYSIS_TAGS);
        var combinedDecision = SastAuditEligibility.evaluate(
                issue, SastAuditMode.REAUDIT_AVIATOR_AND_HUMAN, RELEVANT_TAGS, ANALYSIS_TAGS);

        assertFalse(aviatorDecision.eligible());
        assertEquals(SastAuditEligibility.Reason.EXCLUDED_HUMAN_AUDIT, aviatorDecision.reason());
        assertTrue(combinedDecision.eligible());
        assertEquals(SastAuditEligibility.Reason.ELIGIBLE_HUMAN_REAUDIT, combinedDecision.reason());
    }

    @Test
    void normalAndAviatorModesPreserveExistingEligibilityRules() {
        var unaudited = SastAuditEligibility.evaluate(
                issue(Map.of(), Map.of()), SastAuditMode.UNAUDITED, RELEVANT_TAGS, ANALYSIS_TAGS);
        var previousAviatorAudit = issue(
                Map.of(Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR), Map.of());
        var normalDecision = SastAuditEligibility.evaluate(
                previousAviatorAudit, SastAuditMode.UNAUDITED, RELEVANT_TAGS, ANALYSIS_TAGS);
        var aviatorDecision = SastAuditEligibility.evaluate(
                previousAviatorAudit, SastAuditMode.REAUDIT_AVIATOR, RELEVANT_TAGS, ANALYSIS_TAGS);
        var combinedDecision = SastAuditEligibility.evaluate(
                previousAviatorAudit, SastAuditMode.REAUDIT_AVIATOR_AND_HUMAN, RELEVANT_TAGS, ANALYSIS_TAGS);

        assertEquals(SastAuditEligibility.Reason.ELIGIBLE_UNAUDITED, unaudited.reason());
        assertEquals(SastAuditEligibility.Reason.EXCLUDED_AVIATOR_AUDIT, normalDecision.reason());
        assertEquals(SastAuditEligibility.Reason.ELIGIBLE_AVIATOR_REAUDIT, aviatorDecision.reason());
        assertEquals(SastAuditEligibility.Reason.ELIGIBLE_AVIATOR_REAUDIT, combinedDecision.reason());
    }

    @Test
    void humanOwnershipRequiresHistoryForTheCurrentDecision() {
        AuditIssue issueWithoutHistory = issue(
                Map.of(Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE), Map.of());
        AuditIssue humanOwned = issue(
                Map.of(Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE),
                Map.of(Constants.ANALYSIS_TAG_ID, "analyst.user"));
        AuditIssue blankOwner = issue(
                Map.of(Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE),
                Map.of(Constants.ANALYSIS_TAG_ID, "   "));

        var unknownOwner = SastAuditEligibility.evaluate(
                issueWithoutHistory, SastAuditMode.REAUDIT_AVIATOR_AND_HUMAN, RELEVANT_TAGS, ANALYSIS_TAGS);
        var blankOwnerDecision = SastAuditEligibility.evaluate(
                blankOwner, SastAuditMode.REAUDIT_AVIATOR_AND_HUMAN, RELEVANT_TAGS, ANALYSIS_TAGS);
        var humanOwner = SastAuditEligibility.evaluate(
                humanOwned, SastAuditMode.REAUDIT_AVIATOR_AND_HUMAN, RELEVANT_TAGS, ANALYSIS_TAGS);

        assertEquals(SastAuditEligibility.Reason.EXCLUDED_ALREADY_AUDITED, unknownOwner.reason());
        assertEquals(SastAuditEligibility.Reason.EXCLUDED_ALREADY_AUDITED, blankOwnerDecision.reason());
        assertEquals(SastAuditEligibility.Reason.ELIGIBLE_HUMAN_REAUDIT, humanOwner.reason());
    }

    @Test
    void configuredResultTagAndLegacyAviatorUsernameDetermineOwnershipPerTag() {
        String configuredResultTag = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        Set<String> relevantTags = Set.of(
                Constants.ANALYSIS_TAG_ID, Constants.AUDITOR_STATUS_TAG_ID, Constants.FOD_TAG_ID, configuredResultTag);
        AuditIssue humanResult = issue(
                Map.of(configuredResultTag, Constants.EXPLOITABLE),
                Map.of(configuredResultTag, "analyst.user"));
        AuditIssue legacyAviatorResult = issue(
                Map.of(configuredResultTag, Constants.EXPLOITABLE),
                Map.of(configuredResultTag, Constants.USER_NAME_LEGACY_FORTIFY_AVIATOR));

        var humanDecision = SastAuditEligibility.evaluate(
                humanResult, SastAuditMode.REAUDIT_AVIATOR_AND_HUMAN, relevantTags, ANALYSIS_TAGS);
        var legacyDecision = SastAuditEligibility.evaluate(
                legacyAviatorResult, SastAuditMode.REAUDIT_AVIATOR, relevantTags, ANALYSIS_TAGS);

        assertEquals(SastAuditEligibility.Reason.ELIGIBLE_HUMAN_REAUDIT, humanDecision.reason());
        assertEquals(SastAuditEligibility.Reason.ELIGIBLE_AVIATOR_REAUDIT, legacyDecision.reason());
    }

    @Test
    void suppressionExcludesEveryModeWithoutImplyingHumanOwnership() {
        AuditIssue suppressed = AuditIssue.builder()
                .suppressed(true)
                .tags(Map.of(Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE,
                        Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR))
                .lastTagUsernames(Map.of(Constants.ANALYSIS_TAG_ID, "analyst.user",
                        Constants.AVIATOR_STATUS_TAG_ID, Constants.USER_NAME))
                .build();

        for (SastAuditMode mode : SastAuditMode.values()) {
            var decision = SastAuditEligibility.evaluate(suppressed, mode, RELEVANT_TAGS, ANALYSIS_TAGS);

            assertFalse(decision.eligible(), mode.name());
            assertEquals(SastAuditEligibility.Reason.EXCLUDED_SUPPRESSED, decision.reason(), mode.name());
        }
    }

    private static AuditIssue issue(Map<String, String> tags, Map<String, String> usernames) {
        return AuditIssue.builder().tags(tags).lastTagUsernames(usernames).build();
    }
}