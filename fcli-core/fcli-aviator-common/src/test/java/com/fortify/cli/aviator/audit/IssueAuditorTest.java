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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fortify.cli.aviator.audit.model.AuditFprOptions;
import com.fortify.cli.aviator.audit.model.FilterSelection;
import com.fortify.cli.aviator.audit.model.SastAuditMode;
import com.fortify.cli.aviator.audit.model.UserPrompt;
import com.fortify.cli.aviator.config.IAviatorLogger;
import com.fortify.cli.aviator.fpr.Vulnerability;
import com.fortify.cli.aviator.fpr.filter.Filter;
import com.fortify.cli.aviator.fpr.filter.FilterSet;
import com.fortify.cli.aviator.fpr.filter.FilterTemplate;
import com.fortify.cli.aviator.fpr.filter.FolderDefinition;
import com.fortify.cli.aviator.fpr.model.AuditIssue;
import com.fortify.cli.aviator.fpr.model.FPRInfo;
import com.fortify.cli.aviator.fpr.model.FVDLMetadata;
import com.fortify.cli.aviator.util.Constants;
import com.fortify.cli.aviator.util.FprHandle;


class IssueAuditorTest {

    private static final String TEST_ISSUE_ID = "PROCESSED_ISSUE";
    private static final IAviatorLogger NO_OP_LOGGER = new IAviatorLogger() {
        @Override public void progress(String format, Object... args) {}
        @Override public void info(String format, Object... args) {}
        @Override public void warn(String format, Object... args) {}
        @Override public void error(String format, Object... args) {}
    };

    private Path tempFprFile;
    private FprHandle fprHandle;

    @BeforeEach
    void setup() throws IOException {
        // 1. Create a temporary dummy FPR file (ZIP format)
        tempFprFile = Files.createTempFile("test_aviator", ".fpr");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(tempFprFile))) {

            // A. Add a minimal audit.fvdl
            ZipEntry entry = new ZipEntry("audit.fvdl");
            zos.putNextEntry(entry);
            String minimalXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><FVDL><UUID>test-uuid</UUID><Build><BuildID>test-build</BuildID></Build></FVDL>";
            zos.write(minimalXml.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // B. Add src-archive/index.xml to suppress the warning
            ZipEntry indexEntry = new ZipEntry("src-archive/index.xml");
            zos.putNextEntry(indexEntry);
            String indexXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><index></index>";
            zos.write(indexXml.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        fprHandle = new FprHandle(tempFprFile);
    }

    @AfterEach
    void tearDown() throws IOException {
        if (fprHandle != null) {
            fprHandle.close();
        }
        if (tempFprFile != null) {
            Files.deleteIfExists(tempFprFile);
        }
    }

    @Test
    void testFprInfoMissingBuildIdDefaultsToEmptyString() throws Exception {
        if (fprHandle != null) {
            fprHandle.close();
            fprHandle = null;
        }
        if (tempFprFile != null) {
            Files.deleteIfExists(tempFprFile);
        }

        tempFprFile = Files.createTempFile("test_aviator_missing_build", ".fpr");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(tempFprFile))) {
            ZipEntry entry = new ZipEntry("audit.fvdl");
            zos.putNextEntry(entry);
            String minimalXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><FVDL><UUID>test-uuid</UUID><Build></Build></FVDL>";
            zos.write(minimalXml.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            ZipEntry indexEntry = new ZipEntry("src-archive/index.xml");
            zos.putNextEntry(indexEntry);
            String indexXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><index></index>";
            zos.write(indexXml.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        fprHandle = new FprHandle(tempFprFile);
        FPRInfo fprInfo = new FPRInfo(fprHandle);

        assertEquals("", fprInfo.getBuildId());
    }

    @Test
    void skipsPreviouslyProcessedAviatorIssueWithoutForceReaudit() throws Exception {
        IssueAuditor auditor = createIssueAuditor(false, false,
                Map.of(Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR));

        assertTrue(prepareIssueIds(auditor).isEmpty());
    }

    @Test
    void forceReauditIncludesProcessedAviatorIssueAndIgnoresAviatorOutcomeTag() throws Exception {
        IssueAuditor auditor = createIssueAuditor(true, false, Map.of(
                Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR,
                Constants.AVIATOR_EXPECTED_OUTCOME_TAG_ID, Constants.EXPLOITABLE));

        assertEquals(List.of(TEST_ISSUE_ID), prepareIssueIds(auditor));
    }

    @Test
    void forceReauditIncludesProcessedAviatorIssueWithAnalysisTag() throws Exception {
        IssueAuditor auditor = createIssueAuditor(true, false, Map.of(
                Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR,
                Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE));

        assertEquals(List.of(TEST_ISSUE_ID), prepareIssueIds(auditor));
    }

    @Test
    void forceReauditStillSkipsSuppressedIssue() throws Exception {
        IssueAuditor auditor = createIssueAuditor(true, true,
                Map.of(Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR));

        assertTrue(prepareIssueIds(auditor).isEmpty());
    }

    @Test
    void forceReauditDoesNotAssumeHumanOwnershipWithoutTagHistory() throws Exception {
        IssueAuditor auditor = createIssueAuditor(true, false, Map.of(
                Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR,
                Constants.FOD_TAG_ID, Constants.EXPLOITABLE));

        assertEquals(List.of(TEST_ISSUE_ID), prepareIssueIds(auditor));
    }

    @Test
    void includeHumanModeReauditsHumanOnlyIssues() throws Exception {
        Map<String, String> tags = Map.of(Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE);
        Map<String, String> writers = Map.of(Constants.ANALYSIS_TAG_ID, "analyst.user");

        assertTrue(prepareIssueIds(createIssueAuditor(SastAuditMode.REAUDIT_AVIATOR, false, tags, writers)).isEmpty());
        assertEquals(List.of(TEST_ISSUE_ID), prepareIssueIds(
            createIssueAuditor(SastAuditMode.REAUDIT_AVIATOR_AND_HUMAN, false, tags, writers)));
    }

    @Test
    void humanAnalysisOwnershipIsNotReplacedByAviatorStatusOwnership() throws Exception {
        Map<String, String> tags = Map.of(
            Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE,
            Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR);
        Map<String, String> writers = Map.of(
            Constants.ANALYSIS_TAG_ID, "analyst.user",
            Constants.AVIATOR_STATUS_TAG_ID, Constants.USER_NAME);

        assertTrue(prepareIssueIds(createIssueAuditor(SastAuditMode.REAUDIT_AVIATOR, false, tags, writers)).isEmpty());
        assertEquals(List.of(TEST_ISSUE_ID), prepareIssueIds(
            createIssueAuditor(SastAuditMode.REAUDIT_AVIATOR_AND_HUMAN, false, tags, writers)));
    }

    @Test
    void forceReauditStillAppliesFilterSetAndFolderRestrictions() throws Exception {
        FilterSet filterSet = new FilterSet();
        filterSet.setTitle("Selected folder");
        filterSet.setFilters(List.of());
        FolderDefinition folder = new FolderDefinition();
        folder.setId("selected-folder-id");
        folder.setName("Selected");
        filterSet.setFolderDefinitions(List.of(folder));
        IssueAuditor auditor = createIssueAuditorWithSelection(SastAuditMode.REAUDIT_AVIATOR, false,
            Map.of(Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR), Map.of(),
            new FilterSelection(filterSet, List.of("Selected")));

        assertTrue(prepareIssueIds(auditor).isEmpty());
    }

    @Test
    void quotaPriorityRunsOnlyOnEligiblePrompts() throws Exception {
        Vulnerability humanCritical = vulnerability("human-critical", "Critical");
        Vulnerability aviatorHigh = vulnerability("aviator-high", "High");
        Vulnerability aviatorLow = vulnerability("aviator-low", "Low");
        Map<String, AuditIssue> auditIssues = Map.of(
            "human-critical", AuditIssue.builder()
                .tags(Map.of(Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE))
                .lastTagUsernames(Map.of(Constants.ANALYSIS_TAG_ID, "analyst.user"))
                .build(),
            "aviator-high", AuditIssue.builder()
                .tags(Map.of(Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR)).build(),
            "aviator-low", AuditIssue.builder()
                .tags(Map.of(Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR)).build());
        FPRInfo fprInfo = new FPRInfo(fprHandle);
        FilterTemplate filterTemplate = new FilterTemplate();
        filterTemplate.setTagDefinitions(new ArrayList<>());
        fprInfo.setFilterTemplate(filterTemplate);
        IssueAuditor auditor = IssueAuditor.builder()
            .vulnerabilities(List.of(humanCritical, aviatorHigh, aviatorLow))
            .auditIssueMap(auditIssues)
            .fprInfo(fprInfo)
            .filterSelection(new FilterSelection(null, null))
            .sourceLanguageResolver(new SourceLanguageResolver(new FVDLMetadata()))
            .options(auditOptions(SastAuditMode.REAUDIT_AVIATOR, NO_OP_LOGGER, null))
            .build();

        List<UserPrompt> eligiblePrompts = auditor.preparePrompts();
        List<UserPrompt> selectedPrompts = QuotaBasedFilter.filterByQuota(eligiblePrompts, 1);

        assertEquals(List.of("aviator-high", "aviator-low"), eligiblePrompts.stream()
            .map(prompt -> prompt.getIssueData().getInstanceID()).toList());
        assertEquals(List.of("aviator-high"), selectedPrompts.stream()
            .map(prompt -> prompt.getIssueData().getInstanceID()).toList());
    }

    @Test
    void forceReauditIncludesIssueWithPendingReviewState() throws Exception {
        IssueAuditor auditor = createIssueAuditor(true, false, Map.of(
                Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR,
                Constants.FOD_TAG_ID, "Pending Review",
                Constants.AUDITOR_STATUS_TAG_ID, Constants.PENDING_REVIEW));

        assertEquals(List.of(TEST_ISSUE_ID), prepareIssueIds(auditor));
    }

    @Test
    void treatsAllPendingAnalysisValuesAsUnaudited() throws Exception {
        for (String pendingValue : List.of("Pending Review", "Not Set", "Pending Review/Not Set", " pending review ")) {
            IssueAuditor auditor = createIssueAuditor(false, false, Map.of(Constants.ANALYSIS_TAG_ID, pendingValue));

            assertEquals(List.of(TEST_ISSUE_ID), prepareIssueIds(auditor), pendingValue);
        }
    }

    @Test
    void forceReauditStillSkipsIssueWithManualAuditorStatus() throws Exception {
        IssueAuditor auditor = createIssueAuditor(true, false, Map.of(
                Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR,
                Constants.AUDITOR_STATUS_TAG_ID, Constants.EXPLOITABLE),
                Map.of(Constants.AUDITOR_STATUS_TAG_ID, "analyst.user"));

        assertTrue(prepareIssueIds(auditor).isEmpty());
    }

    @Test
    void forceReauditIncludesAviatorWrittenAuditorStatus() throws Exception {
        IssueAuditor auditor = createIssueAuditor(true, false, Map.of(
                Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR,
                Constants.AUDITOR_STATUS_TAG_ID, Constants.EXPLOITABLE),
                Map.of(Constants.AUDITOR_STATUS_TAG_ID, Constants.USER_NAME));

        assertEquals(List.of(TEST_ISSUE_ID), prepareIssueIds(auditor));
    }

    @Test
    void forceReauditSkipsHumanAnalysisOverrideAfterAviator() throws Exception {
        IssueAuditor auditor = createIssueAuditor(true, false, Map.of(
                Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR,
                Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE),
                Map.of(Constants.ANALYSIS_TAG_ID, "analyst.user"));

        assertTrue(prepareIssueIds(auditor).isEmpty());
    }

    @Test
    void forceReauditIncludesLegacyFortifyAviatorUsername() throws Exception {
        IssueAuditor auditor = createIssueAuditor(true, false, Map.of(
                Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR,
                Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE),
                Map.of(Constants.ANALYSIS_TAG_ID, Constants.USER_NAME_LEGACY_FORTIFY_AVIATOR));

        assertEquals(List.of(TEST_ISSUE_ID), prepareIssueIds(auditor));
    }

    @Test
    void forceReauditIncludesLegacyAnalysisTagWrittenByAviatorWithoutStatusTag() throws Exception {
        IssueAuditor auditor = createIssueAuditor(true, false,
                Map.of(Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE),
                Map.of(Constants.ANALYSIS_TAG_ID, Constants.USER_NAME_LEGACY_FORTIFY_AVIATOR));

        assertEquals(List.of(TEST_ISSUE_ID), prepareIssueIds(auditor));
    }

    @Test
    void forceReauditSkipsLegacyAnalysisTagWrittenByHumanWithoutStatusTag() throws Exception {
        IssueAuditor auditor = createIssueAuditor(true, false,
                Map.of(Constants.ANALYSIS_TAG_ID, Constants.EXPLOITABLE),
                Map.of(Constants.ANALYSIS_TAG_ID, "analyst.user"));

        assertTrue(prepareIssueIds(auditor).isEmpty());
    }

    @Test
    void forceReauditIncludesMappedTagWrittenByAviatorWithoutStatusTag() throws Exception {
        Path mappingFile = writeMappedTagFile();
        try {
            IssueAuditor auditor = createIssueAuditor(true, false,
                    Map.of("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Constants.EXPLOITABLE),
                    Map.of("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Constants.USER_NAME),
                    mappingFile.toString());
            assertEquals(List.of(TEST_ISSUE_ID), prepareIssueIds(auditor));
        } finally {
            Files.deleteIfExists(mappingFile);
        }
    }

    @Test
    void forceReauditSkipsHumanWriterOnMappedTag() throws Exception {
        Path mappingFile = writeMappedTagFile();
        try {
            IssueAuditor auditor = createIssueAuditor(true, false,
                    Map.of("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Constants.EXPLOITABLE),
                    Map.of("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "analyst.user"),
                    mappingFile.toString());
            assertTrue(prepareIssueIds(auditor).isEmpty());
        } finally {
            Files.deleteIfExists(mappingFile);
        }
    }

    private Path writeMappedTagFile() throws IOException {
        Path mappingFile = Files.createTempFile("tag-mapping", ".yaml");
        Files.writeString(mappingFile, "tag_id: \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"\n");
        return mappingFile;
    }

    private IssueAuditor createIssueAuditor(boolean forceReaudit, boolean suppressed, Map<String, String> tags) {
        return createIssueAuditor(forceReaudit ? SastAuditMode.REAUDIT_AVIATOR : SastAuditMode.UNAUDITED,
                suppressed, tags, Map.of(), null);
    }

    private IssueAuditor createIssueAuditor(boolean forceReaudit, boolean suppressed, Map<String, String> tags,
            Map<String, String> lastTagUsernames) {
        return createIssueAuditor(forceReaudit ? SastAuditMode.REAUDIT_AVIATOR : SastAuditMode.UNAUDITED,
            suppressed, tags, lastTagUsernames, null);
    }

    private IssueAuditor createIssueAuditor(boolean forceReaudit, boolean suppressed, Map<String, String> tags,
            Map<String, String> lastTagUsernames, String tagMappingPath) {
        return createIssueAuditor(forceReaudit ? SastAuditMode.REAUDIT_AVIATOR : SastAuditMode.UNAUDITED,
                suppressed, tags, lastTagUsernames, tagMappingPath);
    }

    private IssueAuditor createIssueAuditor(SastAuditMode mode, boolean suppressed, Map<String, String> tags,
            Map<String, String> lastTagUsernames) {
        return createIssueAuditor(mode, suppressed, tags, lastTagUsernames, null, new FilterSelection(null, null));
    }

    private IssueAuditor createIssueAuditorWithSelection(SastAuditMode mode, boolean suppressed,
            Map<String, String> tags, Map<String, String> lastTagUsernames, FilterSelection filterSelection) {
        return createIssueAuditor(mode, suppressed, tags, lastTagUsernames, (String) null, filterSelection);
    }

    private IssueAuditor createIssueAuditor(SastAuditMode mode, boolean suppressed, Map<String, String> tags,
            Map<String, String> lastTagUsernames, String tagMappingPath) {
        return createIssueAuditor(mode, suppressed, tags, lastTagUsernames, tagMappingPath,
                new FilterSelection(null, null));
    }

    private IssueAuditor createIssueAuditor(SastAuditMode mode, boolean suppressed, Map<String, String> tags,
            Map<String, String> lastTagUsernames, String tagMappingPath, FilterSelection filterSelection) {
        FPRInfo fprInfo = new FPRInfo(fprHandle);
        FilterTemplate filterTemplate = new FilterTemplate();
        filterTemplate.setTagDefinitions(new ArrayList<>());
        fprInfo.setFilterTemplate(filterTemplate);

        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setInstanceID(TEST_ISSUE_ID);
        AuditIssue auditIssue = AuditIssue.builder()
                .instanceId(TEST_ISSUE_ID)
                .suppressed(suppressed)
                .tags(new HashMap<>(tags))
                .lastTagUsernames(new HashMap<>(lastTagUsernames))
                .build();

        return IssueAuditor.builder()
                .vulnerabilities(List.of(vulnerability))
                .auditIssueMap(Map.of(TEST_ISSUE_ID, auditIssue))
                .fprInfo(fprInfo)
                .filterSelection(filterSelection)
                .sourceLanguageResolver(new SourceLanguageResolver(new FVDLMetadata()))
                .options(auditOptions(mode, NO_OP_LOGGER, tagMappingPath))
                .build();
    }

    private AuditFprOptions auditOptions(boolean forceReaudit, IAviatorLogger logger, String tagMappingPath) {
        return auditOptions(forceReaudit ? SastAuditMode.REAUDIT_AVIATOR : SastAuditMode.UNAUDITED,
                logger, tagMappingPath);
    }

    private AuditFprOptions auditOptions(SastAuditMode mode, IAviatorLogger logger, String tagMappingPath) {
        return AuditFprOptions.builder()
                .fprHandle(fprHandle)
                .logger(logger)
                .sscAppName("TestApp")
                .sscAppVersion("1.0")
                .tagMappingPath(tagMappingPath)
                .mode(mode)
                .build();
    }

    private Vulnerability vulnerability(String issueId, String priority) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setInstanceID(issueId);
        vulnerability.setPriority(priority);
        return vulnerability;
    }

    private List<String> prepareIssueIds(IssueAuditor auditor) throws Exception {
        return auditor.preparePrompts().stream()
                .map(prompt -> prompt.getIssueData().getInstanceID())
                .collect(Collectors.toList());
    }

    @Test
    void testFilterVulnerabilities_LegacySyntaxWithSpaces() throws Exception {

        // Manual Logger Stub (No-op)
        IAviatorLogger dummyLogger = new IAviatorLogger() {
            @Override public void progress(String format, Object... args) {}
            @Override public void info(String format, Object... args) {}
            @Override public void warn(String format, Object... args) {}
            @Override public void error(String format, Object... args) {}
        };

        FPRInfo fprInfo = new FPRInfo(fprHandle);

        FilterTemplate dummyTemplate = new FilterTemplate();
        dummyTemplate.setTagDefinitions(new ArrayList<>());
        // Note: FPRInfo.setFilterTemplate() exists in the provided code
        fprInfo.setFilterTemplate(dummyTemplate);

        // --- 2. SETUP FILTER SET WITH LEGACY SYNTAX ---
        // The "Buggy" Filter String (Legacy syntax: Space in range AND between terms)
        String legacyQuery = "impact:![2.5, 5.0] [Analysis Type]:!SONATYPE";

        Filter filter = new Filter();
        filter.setAction("hide");
        filter.setQuery(legacyQuery);

        FilterSet filterSet = new FilterSet();
        filterSet.setTitle("Regression Test Set");
        filterSet.setFilters(Collections.singletonList(filter));

        FilterSelection selection = new FilterSelection(filterSet, null);

        // Target Issue: High Impact (4.0), Null Analysis Type.
        // Result: Should NOT be hidden.
        Vulnerability targetVuln = new Vulnerability();
        targetVuln.setInstanceID("TARGET_ISSUE");
        targetVuln.setImpact(4.0);

        // Noise Issue: Low Impact (1.0).
        // Result: Should be hidden.
        Vulnerability hiddenVuln = new Vulnerability();
        hiddenVuln.setInstanceID("HIDDEN_ISSUE");
        hiddenVuln.setImpact(1.0);

        List<Vulnerability> inputList = Arrays.asList(targetVuln, hiddenVuln);

        IssueAuditor auditor = IssueAuditor.builder()
                .vulnerabilities(inputList)
                .auditIssueMap(new HashMap<>())
                .fprInfo(fprInfo)
                .filterSelection(selection)
                .sourceLanguageResolver(new SourceLanguageResolver(new FVDLMetadata()))
                .options(auditOptions(SastAuditMode.REAUDIT_AVIATOR, dummyLogger, null))
                .build();

            List<String> remainingIds = auditor.preparePrompts().stream()
                .map(prompt -> prompt.getIssueData().getInstanceID())
                .collect(Collectors.toList());

        assertEquals(1, remainingIds.size(), "Should verify that exactly one issue remains");
        assertTrue(remainingIds.contains("TARGET_ISSUE"),
            "Regression Failed: IssueAuditor hid the target issue. It likely used the Modern parser on a Legacy query string.");
    }
}
