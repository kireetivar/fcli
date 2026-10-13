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
package com.fortify.cli.aviator.ssc.helper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fortify.aviator.application.Application;
import com.fortify.cli.aviator._common.exception.AviatorSimpleException;
import com.fortify.cli.aviator.audit.DastAuditFprResult;
import com.fortify.cli.aviator.audit.model.FPRAuditResult;
import com.fortify.cli.aviator.audit.model.SastAuditMode;
import com.fortify.cli.aviator.config.AviatorLoggerImpl;
import com.fortify.cli.aviator.grpc.AviatorGrpcClient;
import com.fortify.cli.aviator.grpc.AviatorGrpcClientHelper;
import com.fortify.cli.aviator.util.Constants;
import com.fortify.cli.common.exception.FcliSimpleException;
import com.fortify.cli.common.json.JsonHelper;
import com.fortify.cli.common.output.transform.IActionCommandResultSupplier;
import com.fortify.cli.common.rest.unirest.UnexpectedHttpResponseException;
import com.fortify.cli.ssc._common.rest.ssc.SSCUrls;
import com.fortify.cli.ssc.appversion.helper.SSCAppVersionDescriptor;
import com.fortify.cli.ssc.issue.helper.SSCIssueFilterSetDescriptor;
import com.fortify.cli.ssc.issue.helper.SSCIssueFilterSetHelper;

import kong.unirest.GetRequest;
import kong.unirest.UnirestInstance;

/**
 * Helper class for the AviatorSSCAuditCommand to encapsulate
 * result message formatting, JSON output construction, and pre-audit checks.
 */
public final class AviatorSSCAuditHelper {
    private static final Logger LOG = LoggerFactory.getLogger(AviatorSSCAuditHelper.class);
    private static final int PAGE_LIMIT = 200;
    private AviatorSSCAuditHelper() {}

    /**
     * Builds the final JSON result node for the command output.
     * All fields are always present to ensure a stable, predictable output structure.
     * Fields not applicable to the current action are set to null.
     *
     * <p>Structure:
     * <pre>
     * id, applicationName, versionName, artifactId, __action__
     * operation:
     *   audit: { message, submitted, succeeded, skipped }
     * state:
     *   aviator: { availableQuotaBefore, availableQuotaAfter }
     *   ssc: { issuesByCategory }
     * </pre>
     *
     * @param av The SSCAppVersionDescriptor.
     * @param artifactId The ID of the uploaded artifact, or null if not applicable.
     * @param action The final action string for the output.
     * @return An ObjectNode representing the result.
     */
    public static ObjectNode buildResultNode(SSCAppVersionDescriptor av, String artifactId, String action) {
        ObjectNode result = JsonHelper.getObjectMapper().createObjectNode();
        result.put("id", av.getVersionId());
        result.put("applicationName", av.getApplicationName());
        result.put("versionName", av.getVersionName());
        if (artifactId != null) {
            result.put("artifactId", artifactId);
        } else {
            result.putNull("artifactId");
        }
        result.put(IActionCommandResultSupplier.actionFieldName, action);

        // operation.audit — null by default, populated by setAuditStats or setOperationMessage
        ObjectNode operation = JsonHelper.getObjectMapper().createObjectNode();
        operation.putNull("audit");
        result.set("operation", operation);

        // state.aviator and state.ssc — null sub-objects by default
        ObjectNode state = JsonHelper.getObjectMapper().createObjectNode();
        ObjectNode aviatorState = JsonHelper.getObjectMapper().createObjectNode();
        aviatorState.putNull("availableQuotaBefore");
        aviatorState.putNull("availableQuotaAfter");
        state.set("aviator", aviatorState);
        ObjectNode sscState = JsonHelper.getObjectMapper().createObjectNode();
        sscState.putNull("issuesByCategory");
        state.set("ssc", sscState);
        result.set("state", state);

        return result;
    }

    /**
     * Populates the {@code operation.audit} object on the result node with stats from the FPR audit.
     * Sets message, submitted, succeeded, and skipped fields.
     *
     * @param result The result node to update.
     * @param auditResult The result from the Aviator audit.
     */
    public static void setAuditStats(ObjectNode result, FPRAuditResult auditResult) {
        ObjectNode audit = JsonHelper.getObjectMapper().createObjectNode();
        String message;
        switch (auditResult.getStatus()) {
            case "AUDITED":
                message = "Audit completed successfully";
                break;
            case "PARTIALLY_AUDITED":
                message = auditResult.getMessage() != null ? auditResult.getMessage() : "Audit partially completed";
                break;
            case "SKIPPED":
                message = auditResult.getMessage() != null ? auditResult.getMessage() : "No issues to audit";
                break;
            case "FAILED":
                message = auditResult.getMessage() != null ? auditResult.getMessage() : "Audit failed";
                break;
            default:
                message = auditResult.getMessage() != null ? auditResult.getMessage() : "Unknown audit status";
                break;
        }
        audit.put("message", message);
        audit.put("submitted", auditResult.getIssuesSubmitted());
        audit.put("succeeded", auditResult.getIssuesSuccessfullyAudited());
        audit.put("skipped", auditResult.getIssuesSkipped());
        audit.put("skippedReasons", formatSkippedReasons(auditResult.getSkippedByReason()));
        audit.set("skippedByReason", toObjectNode(auditResult.getSkippedByReason()));
        audit.put("remediationGenerationSkipped", auditResult.getRemediationGenerationSkipped());
        audit.put("remediationGenerationSkippedReasons", formatSkippedReasons(auditResult.getRemediationGenerationSkippedByReason()));
        audit.set("remediationGenerationSkippedByReason", toObjectNode(auditResult.getRemediationGenerationSkippedByReason()));
        ((ObjectNode) result.get("operation")).set("audit", audit);
    }

    private static ObjectNode toObjectNode(Map<String, Integer> skippedByReason) {
        ObjectNode object = JsonHelper.getObjectMapper().createObjectNode();
        if (skippedByReason != null) {
            skippedByReason.forEach(object::put);
        }
        return object;
    }

    private static String formatSkippedReasons(Map<String, Integer> skippedByReason) {
        if (skippedByReason == null || skippedByReason.isEmpty()) {
            return "";
        }
        List<String> parts = new ArrayList<>();
        skippedByReason.forEach((reason, count) -> parts.add(reason + "=" + count));
        return String.join(", ", parts);
    }

    /**
     * Populates the standard audit output envelope with DAST-specific statistics.
     *
     * @param result The result node created by {@link #buildResultNode}.
     * @param auditResult The DAST FPR audit result.
     */
    public static void setDastAuditStats(ObjectNode result, DastAuditFprResult auditResult) {
        ObjectNode audit = JsonHelper.getObjectMapper().createObjectNode();
        audit.put("message", getDastAuditMessage(auditResult));
        audit.put("submitted", auditResult.submitted());
        audit.put("succeeded", auditResult.succeeded());
        audit.put("skipped", auditResult.skipped());
        audit.put("failed", auditResult.failed());
        ((ObjectNode) result.get("operation")).set("audit", audit);
        result.remove("state");
    }

    private static String getDastAuditMessage(DastAuditFprResult auditResult) {
        return switch (auditResult.status()) {
            case AUDITED -> "DAST audit completed successfully";
            case PARTIALLY_AUDITED -> auditResult.message() != null
                ? auditResult.message() : "DAST audit partially completed";
            case SKIPPED -> auditResult.message() != null
                ? auditResult.message() : "No DAST findings to audit";
            case FAILED -> auditResult.message() != null
                ? auditResult.message() : "DAST audit failed";
        };
    }

    /**
     * Sets only the {@code operation.audit.message} field without audit stats.
     * Used for code paths that don't perform an actual audit (SKIPPED, FAILED, QUOTA_EXCEEDED, etc.).
     *
     * @param result The result node to update.
     * @param message The descriptive message.
     */
    public static void setOperationMessage(ObjectNode result, String message) {
        ObjectNode audit = JsonHelper.getObjectMapper().createObjectNode();
        audit.put("message", message);
        audit.putNull("submitted");
        audit.putNull("succeeded");
        audit.putNull("skipped");
        ((ObjectNode) result.get("operation")).set("audit", audit);
    }

    /**
     * Sets the {@code state.aviator.availableQuotaBefore} field.
     *
     * @param result The result node to update.
     * @param quota The quota value.
     */
    public static void setAvailableQuotaBefore(ObjectNode result, long quota) {
        ((ObjectNode) result.path("state").path("aviator")).put("availableQuotaBefore", quota);
    }

    /**
     * Generates a progress message for the user based on the FPRAuditResult.
     * @param auditResult The result from the Aviator audit.
     * @return A user-friendly progress message.
     */
    public static String getProgressMessage(FPRAuditResult auditResult) {
        switch (auditResult.getStatus()) {
            case "SKIPPED":
                return (auditResult.getMessage() != null ? auditResult.getMessage() : "No issues to audit")
                        + ", skipping upload";
            case "FAILED":
                String message = auditResult.getMessage() != null ? auditResult.getMessage() : "Unknown error";
                return "Audit failed: " + message;
            case "PARTIALLY_AUDITED":
            case "AUDITED":
                return auditResult.getUpdatedFile() != null
                        ? "Status: Uploading audited FPR to SSC"
                        : "Audit completed but no file updated";
            default:
                return "Unknown audit status";
        }
    }

    /**
     * Coarse SSC download gate. Re-audit modes query all visible, non-suppressed
     * issues. The prepared FPR selection makes the final eligibility decision.
     */
    public static long getPreliminaryCandidateCount(UnirestInstance unirest, SSCAppVersionDescriptor av, AviatorLoggerImpl logger,
            boolean noFilterSet, String filterSetTitleOrId, List<String> folderNames, SastAuditMode mode) {
        logger.progress("Status: Checking for candidate issues...");
        LOG.debug("Starting preliminary candidate count for SSC version {} (application='{}', version='{}') with pageLimit={}, noFilterSet={}, mode={}",
            av.getVersionId(), av.getApplicationName(), av.getVersionName(), PAGE_LIMIT, noFilterSet, mode);

        PreliminaryCandidateQuery query = resolvePreliminaryCandidateQuery(
                unirest, av, logger, noFilterSet, filterSetTitleOrId, folderNames, mode);
        return countPreliminaryCandidates(query, logger);
    }

    private record PreliminaryCandidateQuery(UnirestInstance unirest, SSCAppVersionDescriptor av, boolean noFilterSet,
            String filterSetGuid, String folderFilter, SastAuditMode mode) {}

    private static PreliminaryCandidateQuery resolvePreliminaryCandidateQuery(UnirestInstance unirest, SSCAppVersionDescriptor av,
            AviatorLoggerImpl logger, boolean noFilterSet, String filterSetTitleOrId, List<String> folderNames,
            SastAuditMode mode) {
        String effectiveFilterSetTitleOrId = filterSetTitleOrId != null && !filterSetTitleOrId.isBlank()
                ? filterSetTitleOrId
                : null;
        boolean effectiveNoFilterSet = noFilterSet && effectiveFilterSetTitleOrId == null;
        SSCIssueFilterSetDescriptor filterSetDescriptor = resolveFilterSet(
                unirest, av, logger, effectiveNoFilterSet, effectiveFilterSetTitleOrId);
        String filterSetGuid = filterSetDescriptor != null ? filterSetDescriptor.getGuid() : null;
        String folderFilter = resolveFolderFilter(logger, av, effectiveNoFilterSet, filterSetDescriptor, folderNames);
        return new PreliminaryCandidateQuery(unirest, av, effectiveNoFilterSet, filterSetGuid, folderFilter, mode);
    }

    private static SSCIssueFilterSetDescriptor resolveFilterSet(UnirestInstance unirest, SSCAppVersionDescriptor av,
            AviatorLoggerImpl logger, boolean noFilterSet, String filterSetTitleOrId) {
        if (noFilterSet) {
            return null;
        }
        SSCIssueFilterSetHelper filterSetHelper = new SSCIssueFilterSetHelper(unirest, av.getVersionId());
        SSCIssueFilterSetDescriptor filterSetDescriptor = filterSetHelper.getDescriptorByTitleOrId(filterSetTitleOrId, false);
        if (filterSetDescriptor != null) {
            logger.progress("Status: Applying filter set '%s' for issue count check", filterSetDescriptor.getTitle());
            LOG.debug("Applied SSC filter set '{}' with guid {} while counting auditable issues for version {}",
                    filterSetDescriptor.getTitle(), filterSetDescriptor.getGuid(), av.getVersionId());
        } else {
            LOG.debug("No SSC filter set resolved from options while counting auditable issues for version {}",
                    av.getVersionId());
        }
        return filterSetDescriptor;
    }

    private static String resolveFolderFilter(AviatorLoggerImpl logger, SSCAppVersionDescriptor av, boolean noFilterSet,
            SSCIssueFilterSetDescriptor filterSetDescriptor, List<String> folderNames) {
        if (folderNames == null || folderNames.isEmpty()) {
            return null;
        }
        String folderFilter = getFolderFilter(noFilterSet, filterSetDescriptor, folderNames);
        logger.progress("Status: Applying folder filter for: %s", String.join(", ", folderNames));
        LOG.debug("Applied folder filter '{}' for folders {} while counting auditable issues for version {}",
                folderFilter, folderNames, av.getVersionId());
        return folderFilter;
    }

    private static long countPreliminaryCandidates(PreliminaryCandidateQuery query, AviatorLoggerImpl logger) {
        try {
            long totalCandidateCount = 0;
            int start = 0;
            long totalFromServer = -1;
            do {
                JsonNode response = fetchAuditableIssuesPage(query, start);
                if (response == null || !response.path("data").isArray()) {
                    LOG.warn("Invalid response received from issue check; proceeding with FPR download.");
                    logger.progress("WARN: Invalid response from issue check. Proceeding with FPR download.");
                    return -1;
                }
                if (totalFromServer == -1) {
                    JsonNode countNode = response.get("count");
                    if (countNode == null || !countNode.isIntegralNumber() || !countNode.canConvertToLong()
                            || countNode.asLong() < 0) {
                        LOG.warn("SSC issue check returned an invalid result count; proceeding with FPR download.");
                        logger.progress("WARN: Incomplete issue count from SSC. Proceeding with FPR download.");
                        return -1;
                    }
                    totalFromServer = countNode.asLong();
                    LOG.debug("SSC reported {} total issues matching the initial auditable count query for version {}",
                            totalFromServer, query.av().getVersionId());
                }
                ArrayNode issues = (ArrayNode) response.get("data");
                if (issues == null || issues.isEmpty()) {
                    if (start < totalFromServer) {
                        LOG.warn("SSC issue check returned an incomplete page at start={}; proceeding with FPR download.", start);
                        logger.progress("WARN: Incomplete issue results from SSC. Proceeding with FPR download.");
                        return -1;
                    }
                    LOG.debug("SSC returned no more issues for version {} at start={}; stopping pagination with cumulativeAuditableCount={} and totalFromServer={}",
                            query.av().getVersionId(), start, totalCandidateCount, totalFromServer);
                    break;
                }
                if (start + issues.size() > totalFromServer) {
                    LOG.warn("SSC issue count changed during preflight; proceeding with FPR download.");
                    logger.progress("WARN: Incomplete issue count from SSC. Proceeding with FPR download.");
                    return -1;
                }
                long candidatesOnPage = countEligibleOnPage(issues, query.mode());
                totalCandidateCount += candidatesOnPage;
                LOG.debug("Processed SSC issues page for version {}: pageStart={}, pageSize={}, auditableOnPage={}, cumulativeAuditableCount={}, totalFromServer={}",
                    query.av().getVersionId(), start, issues.size(), candidatesOnPage, totalCandidateCount, totalFromServer);
                start += issues.size();
            } while (start < totalFromServer);

            if (start < totalFromServer) {
                LOG.warn("SSC issue check did not return all result pages; proceeding with FPR download.");
                logger.progress("WARN: Incomplete issue results from SSC. Proceeding with FPR download.");
                return -1;
            }

                LOG.debug("Completed preliminary candidate count for version {}: totalCandidateCount={}, totalFromServer={}",
                    query.av().getVersionId(), totalCandidateCount, totalFromServer);
                logger.progress("Status: Found %d candidate issues.", totalCandidateCount);
                return totalCandidateCount;
        } catch (UnexpectedHttpResponseException e) {
            LOG.warn("Failed to retrieve auditable issue count from SSC (HTTP {}). This may happen on older SSC versions. Defaulting to downloading the FPR.", e.getStatus(), e);
            logger.progress("WARN: Failed to retrieve issue count from SSC. Proceeding with FPR download as a fallback.");
            return -1;
        }
    }

    private static JsonNode fetchAuditableIssuesPage(PreliminaryCandidateQuery query, int start) {
        GetRequest request = query.unirest().get(SSCUrls.PROJECT_VERSION_ISSUES(query.av().getVersionId()))
                .queryString("limit", PAGE_LIMIT)
                .queryString("embed", "auditValues")
                .queryString("qm", "issues")
                .queryString("start", start);
        if (query.mode() == SastAuditMode.UNAUDITED) {
            request.queryString("q", "audited:false");
        }
        if (query.noFilterSet()) {
            request.queryString("showhidden", "true");
        }
        if (query.filterSetGuid() != null) {
            request.queryString("filterset", query.filterSetGuid());
        }
        if (query.folderFilter() != null) {
            request.queryString("filter", query.folderFilter());
        }
        LOG.debug("Requesting SSC issues page for version {} with start={} and limit={}",
                query.av().getVersionId(), start, PAGE_LIMIT);
        return request.asObject(JsonNode.class).getBody();
    }

    private static long countEligibleOnPage(ArrayNode issues, SastAuditMode mode) {
        return JsonHelper.stream(issues)
                .filter(issue -> isEligibleForRequestedAudit(issue, mode))
                .count();
    }

    private static boolean isEligibleForRequestedAudit(JsonNode issue, SastAuditMode mode) {
        if (issue.path("suppressed").asBoolean(false)) {
            return false;
        }
        return mode != SastAuditMode.UNAUDITED
                || (!issue.path("audited").asBoolean(false) && !isProcessedByAviator(issue));
    }

    /**
     * Checks if an issue has the 'Aviator status' custom tag set.
     */
    private static boolean isProcessedByAviator(JsonNode issue) {
        JsonNode auditValues = issue.path("_embed").path("auditValues");
        if (!auditValues.isArray()) {
            return false;
        }
        String statusTagGuid = AviatorSSCTagDefs.AVIATOR_STATUS_TAG.getGuid();
        return JsonHelper.stream((ArrayNode) auditValues)
                .anyMatch(tagValue ->
                        statusTagGuid.equals(tagValue.path("customTagGuid").asText()) &&
                                tagValue.has("customTagIndex")
                );
    }

    /**
     * Helper method to construct the folder filter string for the API request.
     */
    private static String getFolderFilter(boolean noFilterSet, SSCIssueFilterSetDescriptor filterSetDescriptor, List<String> folderNames) {
        if (noFilterSet) {
            throw new FcliSimpleException("--folder option cannot be used with --no-filterset.");
        }
        if (filterSetDescriptor == null) {
            throw new FcliSimpleException("--folder option requires an active filter set. Use --filterset or ensure a default filter set exists.");
        }

        final JsonNode foldersNode = filterSetDescriptor.asJsonNode().get("folders");
        if (foldersNode == null || !foldersNode.isArray()) {
            throw new FcliSimpleException("Could not retrieve folders for the specified filter set: " + filterSetDescriptor.getTitle());
        }

        Map<String, String> folderNameToGuidMap = new HashMap<>();
        JsonHelper.stream((ArrayNode) foldersNode).forEach(folder ->
                folderNameToGuidMap.put(folder.get("name").asText().toLowerCase(), folder.get("guid").asText())
        );

        final SSCIssueFilterSetDescriptor finalFilterSetDescriptor = filterSetDescriptor;
        return folderNames.stream()
                .map(String::toLowerCase)
                .map(folderName -> {
                    String guid = folderNameToGuidMap.get(folderName);
                    if (guid == null) {
                        String availableFolders = JsonHelper.stream((ArrayNode) foldersNode).map(f -> f.get("name").asText()).collect(Collectors.joining(", "));
                        throw new FcliSimpleException(String.format("Folder '%s' not found in filter set '%s'. Available folders: %s", folderName, finalFilterSetDescriptor.getTitle(), availableFolders));
                    }
                    return String.format("FOLDER:%s", guid);
                })
                .collect(Collectors.joining(" OR "));
    }

    /**
     * Sentinel value indicating quota retrieval failed.
     */
    public static final long QUOTA_UNKNOWN = Long.MIN_VALUE;

    /**
     * Sentinel value indicating the application was not found on the server.
     */
    public static final long QUOTA_APP_NOT_FOUND = Long.MIN_VALUE + 1;

    /**
     * Retrieves the available quota for the given Aviator application using the developer token.
     * Returns the quota value from the server, {@link #QUOTA_APP_NOT_FOUND} if the app doesn't exist,
     * or {@link #QUOTA_UNKNOWN} if retrieval fails for other reasons.
     * A server-returned value of -1 means unlimited quota.
     */
    public static long getAvailableQuota(String aviatorUrl, String aviatorToken, String appName,
                                          AviatorLoggerImpl logger) {
        try (AviatorGrpcClient client = AviatorGrpcClientHelper.createClient(aviatorUrl, logger,
                Constants.DEFAULT_PING_INTERVAL_SECONDS)) {
            Application app = client.getApplicationByToken(aviatorToken, appName);
            long quota = app.getQuota();
            logger.progress("Status: Available Aviator quota for app '%s': %s", appName,
                    quota < 0 ? "unlimited" : String.valueOf(quota));
            return quota;
        } catch (AviatorSimpleException e) {
            if (e.getMessage() != null && e.getMessage().contains("not found")) {
                LOG.info("Application '{}' not found on Aviator server.", appName);
                return QUOTA_APP_NOT_FOUND;
            }
            LOG.warn("Failed to retrieve quota for application '{}': {}", appName, e.getMessage());
            logger.progress("WARN: Could not retrieve Aviator quota for app '%s'. Proceeding without quota check.", appName);
            return QUOTA_UNKNOWN;
        } catch (Exception e) {
            LOG.warn("Failed to retrieve quota for application '{}': {}", appName, e.getMessage());
            logger.progress("WARN: Could not retrieve Aviator quota for app '%s'. Proceeding without quota check.", appName);
            return QUOTA_UNKNOWN;
        }
    }

    /**
     * Retrieves the default initial quota for new applications from the tenant.
     * Returns the default quota, or {@link #QUOTA_UNKNOWN} if retrieval fails.
     */
    public static long getDefaultQuota(String aviatorUrl, String aviatorToken,
                                        AviatorLoggerImpl logger) {
        try (AviatorGrpcClient client = AviatorGrpcClientHelper.createClient(aviatorUrl, logger,
                Constants.DEFAULT_PING_INTERVAL_SECONDS)) {
            long quota = client.getDefaultQuota(aviatorToken);
            logger.progress("Status: Default Aviator quota for new applications: %s",
                    quota < 0 ? "unlimited" : String.valueOf(quota));
            return quota;
        } catch (Exception e) {
            LOG.warn("Failed to retrieve default quota: {}", e.getMessage());
            logger.progress("WARN: Could not retrieve default Aviator quota.");
            return QUOTA_UNKNOWN;
        }
    }

    /**
     * Builds the JSON result node when a version is skipped due to exceeding quota.
     * Sets {@code state.aviator.availableQuotaBefore} and populates {@code state.ssc.issuesByCategory}
     * with total, audited, and unaudited counts per category.
     */
    public static ObjectNode buildQuotaExceededResultNode(
            SSCAppVersionDescriptor av, long openIssueCount, long availableQuota,
            List<Map<String, Object>> topCategories) {
        ObjectNode result = buildResultNode(av, null, "QUOTA_EXCEEDED");
        setOperationMessage(result, String.format("Eligible issues (%d) exceed available quota (%d)", openIssueCount, availableQuota));
        setAvailableQuotaBefore(result, availableQuota);
        ((ObjectNode) result.path("state").path("ssc")).set("issuesByCategory", buildIssuesByCategoryArray(topCategories));
        return result;
    }

    /**
     * Converts the category list into a JSON array for the {@code issuesByCategory} field.
     */
    private static ArrayNode buildIssuesByCategoryArray(List<Map<String, Object>> categories) {
        ArrayNode array = JsonHelper.getObjectMapper().createArrayNode();
        if (categories != null) {
            for (Map<String, Object> cat : categories) {
                ObjectNode catNode = JsonHelper.getObjectMapper().createObjectNode();
                catNode.put("category", (String) cat.get("categoryName"));
                catNode.put("total", (long) cat.get("totalIssues"));
                catNode.put("audited", (long) cat.get("auditedIssues"));
                catNode.put("unaudited", (long) cat.get("unauditedCount"));
                catNode.put("eligible", (long) cat.get("eligibleCount"));
                array.add(catNode);
            }
        }
        return array;
    }

    /**
     * Ranks categories from the exact prepared FPR selection used for quota checks.
     */
    public static List<Map<String, Object>> getTopEligibleCategories(
            Map<String, Integer> eligibleCategoryCounts, int topN) {
        if (eligibleCategoryCounts == null || eligibleCategoryCounts.isEmpty() || topN <= 0) {
            return List.of();
        }
        return eligibleCategoryCounts.entrySet().stream()
                .filter(entry -> entry.getValue() != null && entry.getValue() > 0)
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
                .limit(topN)
                .map(entry -> {
                    long count = entry.getValue();
                    Map<String, Object> category = new LinkedHashMap<>();
                    category.put("categoryName", entry.getKey());
                    category.put("totalIssues", count);
                    category.put("auditedIssues", 0L);
                    category.put("unauditedCount", count);
                    category.put("eligibleCount", count);
                    return category;
                })
                .toList();
    }

    /**
     * Formats a human-readable message for quota exceeded scenarios.
     */
    public static String formatQuotaExceededMessage(
            SSCAppVersionDescriptor av, long openIssueCount, long availableQuota,
            List<Map<String, Object>> topCategories) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Quota exceeded for %s:%s -- Eligible issues: %d, Available quota: %d%n",
            av.getApplicationName(), av.getVersionName(), openIssueCount, availableQuota));
        sb.append("Top SAST categories by eligible issue count:\n");
        if (topCategories != null) {
            int rank = 1;
            for (Map<String, Object> cat : topCategories) {
                sb.append(String.format("  %d. %s (eligible: %d)%n",
                    rank++, cat.get("categoryName"), cat.get("eligibleCount")));
            }
        }
        return sb.toString();
    }
}