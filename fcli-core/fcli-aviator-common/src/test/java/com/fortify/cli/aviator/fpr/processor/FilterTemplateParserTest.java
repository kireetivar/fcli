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
package com.fortify.cli.aviator.fpr.processor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fortify.cli.aviator._common.exception.AviatorTechnicalException;
import com.fortify.cli.aviator.fpr.filter.TagDefinition;
import com.fortify.cli.aviator.util.Constants;
import com.fortify.cli.aviator.util.FprHandle;

@DisplayName("FilterTemplateParser")
class FilterTemplateParserTest {
    @TempDir
    Path tempDir;

    @Test
    @DisplayName("throws AviatorTechnicalException on malformed filtertemplate.xml")
    void throwsTechnicalExceptionOnMalformedFilterTemplateXml() throws Exception {
        Path fprPath = createFpr("<FilterTemplate>");

        try (FprHandle fprHandle = new FprHandle(fprPath)) {
            FilterTemplateParser parser = new FilterTemplateParser(fprHandle, new AuditProcessor(fprHandle));
            AviatorTechnicalException exception = assertThrows(AviatorTechnicalException.class, parser::parseFilterTemplate);

            assertTrue(exception.getMessage().contains("filtertemplate.xml"));
        }
    }

    @Test
    @DisplayName("adds missing Aviator status values to an existing tag definition")
    void addsMissingAviatorStatusValueToExistingTagDefinition() throws Exception {
        Path fprPath = createFpr(filterTemplateWithExistingAviatorStatusTag());

        try (FprHandle fprHandle = new FprHandle(fprPath)) {
            AuditProcessor auditProcessor = new AuditProcessor(fprHandle);
            FilterTemplateParser parser = new FilterTemplateParser(fprHandle, auditProcessor);
            var filterTemplate = parser.parseFilterTemplate().orElseThrow();

            TagDefinition statusTag = filterTemplate.getTagDefinitions().stream()
                    .filter(tag -> Constants.AVIATOR_STATUS_TAG_ID.equalsIgnoreCase(tag.getId()))
                    .findFirst()
                    .orElseThrow();

            assertEquals(2, statusTag.getTagValuesAsString().size());
            assertTrue(statusTag.getTagValuesAsString().contains(Constants.PROCESSED_BY_AVIATOR));
            assertTrue(statusTag.getTagValuesAsString().contains(Constants.PROCESSED_BY_AVIATOR_WITH_REMEDIATION));

            auditProcessor.processAuditXML();
            auditProcessor.updateAndSaveAuditAndRemediationsXml(Map.of(), null, Map.of(), null);

            String updatedFilterTemplate = Files.readString(fprHandle.getPath("/filtertemplate.xml"));
            assertTrue(updatedFilterTemplate.contains(Constants.PROCESSED_BY_AVIATOR_WITH_REMEDIATION));

                var reparsedTemplate = new FilterTemplateParser(fprHandle, new AuditProcessor(fprHandle))
                    .parseFilterTemplate().orElseThrow();
                assertEquals(2, reparsedTemplate.getTagDefinitions().stream()
                    .filter(tag -> Constants.AVIATOR_STATUS_TAG_ID.equalsIgnoreCase(tag.getId()))
                    .findFirst().orElseThrow().getTagValuesAsString().size());
        }
    }

    private Path createFpr(String filterTemplateXml) throws IOException {
        Path fprPath = tempDir.resolve("test.fpr");
        try (ZipOutputStream zipOutputStream = new ZipOutputStream(Files.newOutputStream(fprPath))) {
            writeEntry(zipOutputStream, "filtertemplate.xml", filterTemplateXml);
            writeEntry(zipOutputStream, "audit.xml", """
                <?xml version="1.0" encoding="UTF-8"?>
                <Audit xmlns="xmlns://www.fortify.com/schema/audit" version="4.4">
                    <IssueList/>
                </Audit>
                """);
            writeEntry(zipOutputStream, "src-archive/index.xml", """
                <?xml version=\"1.0\" encoding=\"UTF-8\"?>
                <index>
                    <entry key=\"Test.java\">src-archive/Test.java</entry>
                </index>
                """);
            writeEntry(zipOutputStream, "src-archive/Test.java", "public class Test {}\n");
        }
        return fprPath;
    }

    private String filterTemplateWithExistingAviatorStatusTag() {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <FilterTemplate>
                    <TagDefinition id="%s" valueType="LIST">
                        <name>Aviator status</name>
                        <value id="0" hidden="false">%s</value>
                    </TagDefinition>
                </FilterTemplate>
                """.formatted(Constants.AVIATOR_STATUS_TAG_ID, Constants.PROCESSED_BY_AVIATOR);
    }

    private void writeEntry(ZipOutputStream zipOutputStream, String entryName, String content) throws IOException {
        zipOutputStream.putNextEntry(new ZipEntry(entryName));
        zipOutputStream.write(content.getBytes(StandardCharsets.UTF_8));
        zipOutputStream.closeEntry();
    }
}