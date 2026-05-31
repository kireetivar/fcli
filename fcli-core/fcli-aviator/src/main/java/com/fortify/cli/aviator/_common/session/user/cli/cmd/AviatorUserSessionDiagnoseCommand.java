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
package com.fortify.cli.aviator._common.session.user.cli.cmd;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fortify.cli.aviator._common.exception.AviatorSimpleException;
import com.fortify.cli.aviator._common.session.user.cli.mixin.AviatorOptionalUserTokenResolverMixin;
import com.fortify.cli.aviator._common.session.user.helper.AviatorUserSessionDescriptor;
import com.fortify.cli.aviator._common.session.user.helper.AviatorUserSessionHelper;
import com.fortify.cli.aviator.grpc.AviatorGrpcConnectivityDiagnosticHelper;
import com.fortify.cli.aviator.grpc.AviatorGrpcConnectivityDiagnosticHelper.DiagnosticResult;
import com.fortify.cli.common.cli.cmd.AbstractRunnableCommand.LogLevel;
import com.fortify.cli.common.json.JsonHelper;
import com.fortify.cli.common.json.producer.ObjectNodeProducerApplyFrom;
import com.fortify.cli.common.log.LogSensitivityLevel;
import com.fortify.cli.common.log.MaskValue;
import com.fortify.cli.common.output.cli.cmd.AbstractOutputCommand;
import com.fortify.cli.common.output.cli.cmd.IJsonNodeSupplier;
import com.fortify.cli.common.output.cli.mixin.OutputHelperMixins;
import com.fortify.cli.common.output.writer.record.RecordWriterFactory;
import com.fortify.cli.common.progress.cli.mixin.ProgressWriterFactoryMixin;
import com.fortify.cli.common.progress.helper.IProgressWriterI18n;
import com.fortify.cli.common.util.ConsoleHelper;

import lombok.Getter;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Help.Ansi;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

@Command(name = "diagnose")
public class AviatorUserSessionDiagnoseCommand extends AbstractOutputCommand implements IJsonNodeSupplier {
    @Getter @Mixin private OutputHelperMixins.TableNoQuery outputHelper;
    @Mixin private ProgressWriterFactoryMixin progressWriterFactoryMixin;
    @ArgGroup(exclusive = true, multiplicity = "0..1", order = 1)
    private AviatorSessionUrlOrSessionArgGroup targetOptions = new AviatorSessionUrlOrSessionArgGroup();
    @Mixin private AviatorOptionalUserTokenResolverMixin tokenResolver = new AviatorOptionalUserTokenResolverMixin();
    @Option(names = {"--timeout"}, defaultValue = "10", order = 3)
    private long timeoutSeconds;
    @Option(names = {"--skip-auth"}, order = 4)
    private boolean skipAuth;
    @Option(names = {"--export"}, order = 5)
    private Path exportFile;

    private DiagnosticResult diagnosticResult;

    @Override
    public Integer call() {
        try (IProgressWriterI18n progressWriter = progressWriterFactoryMixin.create()) {
            progressWriter.writeI18nProgress("fcli.aviator.session.diagnose.progress.running", getAviatorUrl());
            DiagnosticResult result = getDiagnosticResult(progressWriter::writeProgress);
            DiagnosticVerdict verdict = createVerdict(result.steps(), result.connectivityFailure());
            ArrayNode outputSteps = prepareOutputSteps(result.steps());
            getOutputHelper().write(simpleObjectNodeProducerBuilder(ObjectNodeProducerApplyFrom.SPEC).source(outputSteps).build());
            exportDiagnosticIfRequested(result, verdict, progressWriter);
            writeVerdict(verdict);
            if ( result.connectivityFailure() ) {
                progressWriter.writeI18nWarning("fcli.aviator.session.diagnose.progress.failed");
                return 1;
            }
            if ( verdict.severity() == DiagnosticSeverity.WARN ) {
                progressWriter.writeI18nWarning("fcli.aviator.session.diagnose.progress.warning");
                return 0;
            }
            progressWriter.writeI18nProgress("fcli.aviator.session.diagnose.progress.succeeded");
            return 0;
        }
    }

    @Override
    public JsonNode getJsonNode() {
        return getDiagnosticResult(null).steps();
    }

    @Override
    public boolean isSingular() {
        return false;
    }

    private DiagnosticResult getDiagnosticResult(java.util.function.Consumer<String> progressConsumer) {
        if ( diagnosticResult == null ) {
            validateOptions();
            diagnosticResult = AviatorGrpcConnectivityDiagnosticHelper.runDiagnostic(
                    getAviatorUrl(),
                    getToken(),
                    timeoutSeconds,
                    skipAuth,
                    progressConsumer
            );
        }
        return diagnosticResult;
    }

    private void validateOptions() {
        if ( timeoutSeconds <= 0 ) {
            throw new AviatorSimpleException("--timeout must be greater than 0");
        }
    }

    private String getAviatorUrl() {
        return targetOptions.hasUrlOption()
                ? targetOptions.getAviatorUrl()
                : targetOptions.getSessionDescriptor().getAviatorUrl();
    }

    private String getToken() {
        String resolvedToken = tokenResolver.getToken();
        if ( StringUtils.isNotBlank(resolvedToken) ) {
            return resolvedToken;
        }
        return targetOptions.hasUrlOption() ? null : targetOptions.getSessionDescriptor().getAviatorToken();
    }

    private ArrayNode prepareOutputSteps(ArrayNode steps) {
        if ( !shouldColorizeTableOutput() ) {
            return steps;
        }
        ArrayNode coloredSteps = steps.deepCopy();
        for ( JsonNode stepNode : coloredSteps ) {
            if ( stepNode instanceof ObjectNode stepObject ) {
                stepObject.put("status", colorizeStatus(stepObject.path("status").asText()));
            }
        }
        return coloredSteps;
    }

    private boolean shouldColorizeTableOutput() {
        var outputWriterFactory = outputHelper.getOutputWriterFactory();
        var outputOptions = outputWriterFactory.getOutputOptionsArgGroup();
        RecordWriterFactory selectedWriterFactory = outputWriterFactory.getSelectedRecordWriterFactory(outputHelper.getBasicOutputConfig());
        return selectedWriterFactory == RecordWriterFactory.table
            && outputOptions.getOutputFile() == null
                && ConsoleHelper.hasTerminal();
    }

    private String colorizeStatus(String status) {
        return switch ( status ) {
            case "OK" -> Ansi.AUTO.string("@|fg(green) OK|@");
            case "WARN" -> Ansi.AUTO.string("@|fg(yellow) WARN|@");
            case "FAILED" -> Ansi.AUTO.string("@|fg(red) FAILED|@");
            case "SKIPPED" -> Ansi.AUTO.string("@|fg(yellow) SKIPPED|@");
            default -> status;
        };
    }

    private DiagnosticVerdict createVerdict(ArrayNode steps, boolean connectivityFailure) {
        JsonNode firstConnectivityFailure = findFirstStep(steps, true, "FAILED");
        if ( firstConnectivityFailure != null ) {
            return DiagnosticVerdict.failure(
                    firstConnectivityFailure.path("step").asText(),
                    firstConnectivityFailure.path("failureCategory").asText(null),
                    firstConnectivityFailure.path("summary").asText(),
                    connectivityFailure
            );
        }

        JsonNode firstFailure = findFirstStep(steps, false, "FAILED");
        if ( firstFailure != null ) {
            return DiagnosticVerdict.warning(
                    firstFailure.path("step").asText(),
                    firstFailure.path("failureCategory").asText(null),
                    firstFailure.path("summary").asText(),
                    "Connectivity OK; a follow-up step failed"
            );
        }

        JsonNode firstWarning = findFirstStep(steps, false, "WARN");
        if ( firstWarning != null ) {
            return DiagnosticVerdict.warning(
                    firstWarning.path("step").asText(),
                    firstWarning.path("failureCategory").asText(null),
                    firstWarning.path("summary").asText(),
                    "Connectivity OK with warnings"
            );
        }

        return DiagnosticVerdict.success("Connectivity OK: all connectivity probes passed");
    }

    private JsonNode findFirstStep(ArrayNode steps, boolean connectivityOnly, String status) {
        for ( JsonNode step : steps ) {
            if ( status.equals(step.path("status").asText())
                    && (!connectivityOnly || AviatorGrpcConnectivityDiagnosticHelper.isConnectivityFailureStep(step)) ) {
                return step;
            }
        }
        return null;
    }

    private void exportDiagnosticIfRequested(DiagnosticResult result, DiagnosticVerdict verdict, IProgressWriterI18n progressWriter) {
        if ( exportFile == null ) {
            return;
        }
        try {
            Path absolutePath = exportFile.toAbsolutePath();
            Path parent = absolutePath.getParent();
            if ( parent != null ) {
                Files.createDirectories(parent);
            }
            ObjectNode exportNode = JsonHelper.getObjectMapper().createObjectNode();
            exportNode.put("generatedAt", Instant.now().toString());
            exportNode.put("targetUrl", getAviatorUrl());
            exportNode.put("targetSource", targetOptions.hasUrlOption() ? "url" : "session");
            if ( !targetOptions.hasUrlOption() ) {
                exportNode.put("aviatorSession", targetOptions.getSessionName());
            }
            exportNode.put("timeoutSeconds", timeoutSeconds);
            exportNode.put("skipAuth", skipAuth);
            exportNode.put("tokenProvided", StringUtils.isNotBlank(getToken()));
            exportNode.put("connectivityFailure", result.connectivityFailure());
            exportNode.set("verdict", verdict.asJson());
            exportNode.set("steps", result.steps());

            Path logFile = resolveActiveLogFile();
            boolean logFileExists = logFile != null && Files.exists(logFile);
            exportNode.put("logFilePath", logFile == null ? "<none>" : logFile.toString());
            exportNode.put("logFileExists", logFileExists);
            if ( logFileExists ) {
                ArrayNode logLines = exportNode.putArray("recentLogLines");
                readRecentLogLines(logFile, 500).forEach(logLines::add);
            }

            JsonHelper.getObjectMapper().writerWithDefaultPrettyPrinter().writeValue(absolutePath.toFile(), exportNode);
            progressWriter.writeI18nProgress("fcli.aviator.session.diagnose.progress.exported", absolutePath);
        } catch ( IOException e ) {
            throw new AviatorSimpleException("Unable to export diagnostic bundle: " + e.getMessage(), e);
        }
    }

    Path resolveActiveLogFile() {
        var genericOptions = getGenericOptions();
        LogLevel logLevel = genericOptions.getLogLevel();
        File logFile = genericOptions.getLogFile();
        if ( logLevel == LogLevel.NONE || (logFile == null && logLevel == null && !genericOptions.isDebug()) ) {
            return null;
        }
        return Path.of(logFile == null ? "fcli.log" : logFile.getAbsolutePath()).toAbsolutePath();
    }

    private List<String> readRecentLogLines(Path logFile, int maxLines) throws IOException {
        if ( maxLines <= 0 ) {
            return List.of();
        }
        Deque<String> recentLines = new ArrayDeque<>(maxLines);
        try (BufferedReader reader = Files.newBufferedReader(logFile)) {
            String line;
            while ( (line = reader.readLine()) != null ) {
                if ( recentLines.size() == maxLines ) {
                    recentLines.removeFirst();
                }
                recentLines.addLast(line);
            }
        }
        return List.copyOf(recentLines);
    }

    private void writeVerdict(DiagnosticVerdict verdict) {
        String message = verdict.toDisplayString();
        String ansiMessage = switch ( verdict.severity() ) {
            case OK -> Ansi.AUTO.string("@|fg(green)" + escapeForAnsi(message) + "|@");
            case WARN -> Ansi.AUTO.string("@|fg(yellow)" + escapeForAnsi(message) + "|@");
            case FAILED -> Ansi.AUTO.string("@|fg(red)" + escapeForAnsi(message) + "|@");
        };
        var err = getCommandHelper().getRootCommandLine().getErr();
        err.println(ConsoleHelper.hasTerminal() ? ansiMessage : message);
        err.flush();
    }

    private String escapeForAnsi(String message) {
        return message.replace("|", "\\|");
    }

    private static final class AviatorSessionUrlOrSessionArgGroup {
        @Option(names = {"--url"}, order = 1)
        @MaskValue(sensitivity = LogSensitivityLevel.low, description = "AVIATOR HOST NAME", pattern = MaskValue.URL_HOSTNAME_PATTERN)
        private String aviatorUrl;
        @Option(names = {"--aviator-session", "--av-session"}, defaultValue = "default", order = 2)
        private String sessionName;

        private boolean hasUrlOption() {
            return StringUtils.isNotBlank(aviatorUrl);
        }

        private String getAviatorUrl() {
            return aviatorUrl;
        }

        private AviatorUserSessionDescriptor getSessionDescriptor() {
            return AviatorUserSessionHelper.instance().get(getSessionName(), true);
        }

        private String getSessionName() {
            return sessionName;
        }
    }

    private record DiagnosticVerdict(DiagnosticSeverity severity, String headline, String step, String failureCategory,
            String summary, boolean connectivityFailure) {
        private static DiagnosticVerdict success(String headline) {
            return new DiagnosticVerdict(DiagnosticSeverity.OK, headline, null, null, null, false);
        }

        private static DiagnosticVerdict warning(String step, String failureCategory, String summary, String headline) {
            return new DiagnosticVerdict(DiagnosticSeverity.WARN, headline, step, failureCategory, summary, false);
        }

        private static DiagnosticVerdict failure(String step, String failureCategory, String summary, boolean connectivityFailure) {
            return new DiagnosticVerdict(DiagnosticSeverity.FAILED, "Connectivity failed", step, failureCategory, summary,
                    connectivityFailure);
        }

        private String toDisplayString() {
            if ( severity == DiagnosticSeverity.OK ) {
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
            return builder.toString();
        }

        private ObjectNode asJson() {
            ObjectNode result = JsonHelper.getObjectMapper().createObjectNode();
            result.put("severity", severity.name());
            result.put("headline", headline);
            result.put("display", toDisplayString());
            result.put("connectivityFailure", connectivityFailure);
            if ( StringUtils.isNotBlank(step) ) {
                result.put("step", step);
            }
            if ( StringUtils.isNotBlank(failureCategory) ) {
                result.put("failureCategory", failureCategory);
            }
            if ( StringUtils.isNotBlank(summary) ) {
                result.put("summary", summary);
            }
            return result;
        }
    }

    private enum DiagnosticSeverity {
        OK,
        WARN,
        FAILED
    }
}