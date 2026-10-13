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

import static com.fortify.cli.aviator.util.Constants.DEFAULT_PING_INTERVAL_SECONDS;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fortify.cli.aviator._common.exception.AviatorQuotaFilterException;
import com.fortify.cli.aviator._common.exception.AviatorSimpleException;
import com.fortify.cli.aviator._common.exception.AviatorTechnicalException;
import com.fortify.cli.aviator.audit.model.AuditFprOptions;
import com.fortify.cli.aviator.audit.model.AuditOutcome;
import com.fortify.cli.aviator.audit.model.AuditResponse;
import com.fortify.cli.aviator.audit.model.FilterSelection;
import com.fortify.cli.aviator.audit.model.UserPrompt;
import com.fortify.cli.aviator.config.TagMappingConfig;
import com.fortify.cli.aviator.fpr.Vulnerability;
import com.fortify.cli.aviator.fpr.filter.Filter;
import com.fortify.cli.aviator.fpr.filter.FilterSet;
import com.fortify.cli.aviator.fpr.filter.FolderDefinition;
import com.fortify.cli.aviator.fpr.filter.TagDefinition;
import com.fortify.cli.aviator.fpr.filter.VulnerabilityFilterer;
import com.fortify.cli.aviator.fpr.model.AuditIssue;
import com.fortify.cli.aviator.fpr.model.FPRInfo;
import com.fortify.cli.aviator.fpr.model.FVDLMetadata;
import com.fortify.cli.aviator.grpc.AviatorGrpcClient;
import com.fortify.cli.aviator.grpc.AviatorGrpcClientHelper;
import com.fortify.cli.aviator.util.Constants;
import com.fortify.cli.aviator.util.ResourceUtil;
import com.fortify.cli.aviator.util.StringUtil;

import lombok.Builder;


public class IssueAuditor {

    private static final Logger LOG = LoggerFactory.getLogger(IssueAuditor.class);

    public final int MAX_PER_CATEGORY;
    public final int MAX_TOTAL;
    public final String MAX_PER_CATEGORY_EXCEEDED;
    public final String MAX_TOTAL_EXCEEDED;
    private final TagDefinition resultsTag;

    public final String SSCApplicationName;
    public final String SSCApplicationVersion;

    private List<Vulnerability> vulnerabilities;
    private final Map<String, AuditIssue> auditIssueMap;
    private final FPRInfo fprInfo;
    private final FilterSelection filterSelection;

    private final TagDefinition analysisTag;
    private final SourceLanguageResolver sourceLanguageResolver;
    private final FVDLMetadata fvdlMetadata;
    private final AuditFprOptions options;
    private final Set<String> resultTagIds;

    @Builder
    public IssueAuditor(List<Vulnerability> vulnerabilities, Map<String, AuditIssue> auditIssueMap,
            FPRInfo fprInfo, FilterSelection filterSelection, SourceLanguageResolver sourceLanguageResolver,
            FVDLMetadata fvdlMetadata, AuditFprOptions options, TagMappingConfig tagMappingConfig) {
        Objects.requireNonNull(options, "options");
        Objects.requireNonNull(options.getSourceDecoder(), "sourceDecoder");
        this.options = options;
        this.MAX_PER_CATEGORY = Constants.MAX_PER_CATEGORY;
        this.MAX_TOTAL = Constants.MAX_TOTAL;
        this.MAX_PER_CATEGORY_EXCEEDED = Constants.MAX_PER_CATEGORY_EXCEEDED;
        this.MAX_TOTAL_EXCEEDED = Constants.MAX_TOTAL_EXCEEDED;
        this.vulnerabilities = vulnerabilities;
        this.auditIssueMap = auditIssueMap;
        this.fprInfo = fprInfo;
        this.filterSelection = filterSelection;
        this.SSCApplicationName = options.getSscAppName();
        this.SSCApplicationVersion = options.getSscAppVersion();
        this.sourceLanguageResolver = sourceLanguageResolver;
        this.fvdlMetadata = fvdlMetadata;
        this.analysisTag = fprInfo.getFilterTemplate().getTagDefinitions().stream().filter(t -> "Analysis".equalsIgnoreCase(t.getName())).findFirst().orElse(null);
        this.resultsTag = resolveResultTag("", "", analysisTag);
        this.resultTagIds = resolveResultTagIds(tagMappingConfig);
    }

    private TagDefinition resolveResultTag(String tagName, String tagGuid, TagDefinition analysisTag) {
        Optional<TagDefinition> existingTag = fprInfo.getFilterTemplate().getTagDefinitions().stream().filter(t -> t.getName().equalsIgnoreCase(tagName)).findFirst();

        if (existingTag.isPresent()) {
            return existingTag.get();
        }

        if (analysisTag != null) {
            return analysisTag;
        }

        List<String> values;
        values = Arrays.asList(Constants.NOT_AN_ISSUE, Constants.EXPLOITABLE);

        return new TagDefinition(tagName, StringUtil.isEmpty(tagGuid) ? UUID.randomUUID().toString() : tagGuid, values, false);
    }

    public AuditOutcome performAudit(Map<String, AuditResponse> auditResponses) {
        return performAudit(preparePrompts(), auditResponses);
    }

    public AuditOutcome performAudit(List<UserPrompt> preparedPrompts, Map<String, AuditResponse> auditResponses) {
        String projectName = StringUtil.isEmpty(options.getAppVersion()) ? fprInfo.getBuildId() : options.getAppVersion();
        options.getLogger().progress("Starting audit for project: %s", projectName);

        ConcurrentLinkedDeque<UserPrompt> promptsToAudit = new ConcurrentLinkedDeque<>(preparedPrompts);
        int totalIssuesToAudit = promptsToAudit.size();
        options.getLogger().progress("Final count of issues to be audited: %d", totalIssuesToAudit);

        if (promptsToAudit.isEmpty()) {
            options.getLogger().progress("Audit skipped - no issues to process after filtering.");
        } else {
            try (AviatorGrpcClient client = AviatorGrpcClientHelper.createClient(options.getUrl(), options.getLogger(), DEFAULT_PING_INTERVAL_SECONDS)) {
                CompletableFuture<Map<String, AuditResponse>> future =
                        client.processBatchRequests(promptsToAudit, projectName, fprInfo.getBuildId(), SSCApplicationName,
                            SSCApplicationVersion, options.getToken(), options.getFprHandle(),
                            options.getFolderPriorityOrder(), options.getSourceDecoder(), fvdlMetadata);
                Map<String, AuditResponse> responses = future.get(500, TimeUnit.MINUTES);
                responses.forEach((requestId, response) -> auditResponses.put(response.getIssueId(), response));
                options.getLogger().progress("Audit completed");
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                // Handle quota filtering exception (all issues filtered out)
                if (cause instanceof AviatorQuotaFilterException) {
                    options.getLogger().progress("All issues filtered out due to quota constraints: %s", cause.getMessage());
                    // Update totalIssuesToAudit to reflect actual auditable count (0)
                    totalIssuesToAudit = 0;
                } else if (cause instanceof AviatorSimpleException) {
                    throw (AviatorSimpleException) cause;
                } else if (cause instanceof AviatorTechnicalException) {
                    throw (AviatorTechnicalException) cause;
                } else {
                    throw new AviatorTechnicalException("Unexpected error during audit execution", cause);
                }
            } catch (TimeoutException e) {
                options.getLogger().error("Audit failed due to timeout after 500 minutes");
                throw new AviatorTechnicalException("Audit timed out after 500 minutes", e);
            } catch (InterruptedException e) {
                options.getLogger().error("Audit failed due to interruption");
                Thread.currentThread().interrupt();
                throw new AviatorTechnicalException("Audit interrupted", e);
            }
        }

        if (resultsTag != null) {
            fprInfo.setResultsTag(resultsTag.getId());
        }
        return new AuditOutcome(auditResponses, totalIssuesToAudit);
    }

    public List<UserPrompt> preparePrompts() {
        FilterSet activeFilterSet = filterSelection.getActiveFilterSet();
        List<Vulnerability> filteredVulnerabilities;

        if (activeFilterSet != null) {
            filteredVulnerabilities = filterVulnerabilities(this.vulnerabilities, activeFilterSet);
        } else {
            LOG.info("No active filter set. All applicable issues will be considered.");
            filteredVulnerabilities = new ArrayList<>(this.vulnerabilities);
        }

        // Convert the filtered vulnerabilities to UserPrompts
        List<UserPrompt> prompts = filteredVulnerabilities.stream()
            .map(vulnerability -> IssueObjBuilder.buildIssueObj(vulnerability, sourceLanguageResolver))
                .collect(Collectors.toList());

        // Apply secondary checks (like 'isAudited')
        prompts = prompts.stream()
                .filter(this::shouldInclude)
                .collect(Collectors.toList());

        return prompts;
    }


    private boolean shouldInclude(UserPrompt userPrompt) {
        AuditIssue auditIssue = auditIssue(userPrompt);
        var decision = SastAuditEligibility.evaluate(
                auditIssue, options.getMode(), resultTagIds, analysisTagIds());
        if (!decision.eligible()) {
            LOG.debug("Skipping issue {}: {}", userPrompt.getIssueData().getInstanceID(), decision.reason());
        }
        return decision.eligible();
    }

    private AuditIssue auditIssue(UserPrompt userPrompt) {
        return auditIssueMap.get(userPrompt.getIssueData().getInstanceID());
    }

    private Set<String> analysisTagIds() {
        Set<String> tagIds = new LinkedHashSet<>(Set.of(Constants.ANALYSIS_TAG_ID));
        if (analysisTag != null && !StringUtil.isEmpty(analysisTag.getId())) {
            tagIds.add(analysisTag.getId());
        }
        return tagIds;
    }

    private Set<String> resolveResultTagIds(TagMappingConfig tagMappingConfig) {
        Set<String> tagIds = new LinkedHashSet<>(List.of(
                Constants.ANALYSIS_TAG_ID, Constants.AUDITOR_STATUS_TAG_ID, Constants.FOD_TAG_ID));
        if (analysisTag != null && !StringUtil.isEmpty(analysisTag.getId())) {
            tagIds.add(analysisTag.getId());
        }
        String mappedTagId = tagMappingConfig == null ? mappedTagId() : tagMappingConfig.getTag_id();
        if (!StringUtil.isEmpty(mappedTagId)) {
            tagIds.add(mappedTagId);
        }
        return tagIds;
    }

    private String mappedTagId() {
        String tagMappingPath = options.getTagMappingPath();
        if (tagMappingPath == null || tagMappingPath.isBlank()) {
            return null;
        }
        try {
            TagMappingConfig config = ResourceUtil.loadYamlFile(new File(tagMappingPath), TagMappingConfig.class);
            return config == null ? null : config.getTag_id();
        } catch (Exception e) {
            LOG.debug("Could not read tag mapping file {}", tagMappingPath, e);
            return null;
        }
    }

    private List<Vulnerability> filterVulnerabilities(List<Vulnerability> allVulnerabilities, FilterSet fs) {
        List<String> targetFolderNames = filterSelection.getTargetFolderNames();

        List<Filter> folderFilters = fs.getFilters().stream()
            .filter(f -> "setFolder".equalsIgnoreCase(f.getAction()))
            .collect(Collectors.toList());

        List<Filter> hideFilters = fs.getFilters().stream()
            .filter(f -> "hide".equalsIgnoreCase(f.getAction()))
            .collect(Collectors.toList());

        Map<String, List<Vulnerability>> folderContents = new HashMap<>();

        // 1. Process "setFolder" filters
        if (folderFilters.isEmpty()) {
            folderContents.put("Default", new ArrayList<>(allVulnerabilities));
        } else {
            for (Filter folderFilter : folderFilters) {
                List<Vulnerability> matches = VulnerabilityFilterer.filter(allVulnerabilities, folderFilter.getQuery());
                folderContents.computeIfAbsent(folderFilter.getActionParam(), k -> new ArrayList<>()).addAll(matches);
            }
        }

        // 2. Process "hide" filters
        for (Filter hideFilter : hideFilters) {
            for (List<Vulnerability> folderList : folderContents.values()) {
                if (folderList.isEmpty()) continue;

                List<Vulnerability> toHide = VulnerabilityFilterer.filter(folderList, hideFilter.getQuery());
                if (!toHide.isEmpty()) {
                    folderList.removeAll(toHide);
                }
            }
        }

        // 3. Selection Logic (Flatten all or select specific folders)
        if (!filterSelection.isFilteringByFolder()) {
            List<Vulnerability> result = folderContents.values().stream()
                .flatMap(List::stream)
                .distinct()
                .collect(Collectors.toList());
            options.getLogger().info("FilterSet '{}' applied. {} of {} total vulnerabilities remain.", fs.getTitle(), result.size(), allVulnerabilities.size());
            return result;
        } else {
            Set<String> targetFolderIds = fs.getFolderDefinitions().stream()
                .filter(fd -> targetFolderNames.stream().anyMatch(name -> name.equalsIgnoreCase(fd.getName())))
                .map(FolderDefinition::getId)
                .collect(Collectors.toSet());

            if (targetFolderIds.isEmpty()) {
                String available = fs.getFolderDefinitions().stream().map(FolderDefinition::getName).collect(Collectors.joining("', '", "'", "'"));
                throw new AviatorSimpleException("Folder(s) not found in FilterSet '"+fs.getTitle()+"'. Available folders: "+available);
            }

            List<Vulnerability> result = folderContents.entrySet().stream()
                .filter(entry -> targetFolderIds.contains(entry.getKey()))
                .flatMap(entry -> entry.getValue().stream())
                .distinct()
                .collect(Collectors.toList());

            options.getLogger().info("Filtered by folder(s) '{}'. {} vulnerabilities remain.", targetFolderNames, result.size());
            return result;
        }
    }
}
