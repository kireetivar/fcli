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
package com.fortify.cli.aviator._main.cli.cmd;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.function.Consumer;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fortify.cli.aviator._common.exception.AviatorSimpleException;
import com.fortify.cli.aviator._common.session.user.helper.AviatorUserSessionDescriptor;
import com.fortify.cli.aviator._common.session.user.helper.AviatorUserSessionHelper;
import com.fortify.cli.aviator.grpc.AviatorGrpcConnectivityDiagnosticHelper;
import com.fortify.cli.aviator.grpc.AviatorGrpcDiagnosticReport;
import com.fortify.cli.aviator.grpc.AviatorGrpcDiagnosticVerdict;
import com.fortify.cli.aviator.grpc.AviatorGrpcDiagnosticVerdict.Severity;
import com.fortify.cli.common.json.JsonHelper;
import com.fortify.cli.common.json.producer.ObjectNodeProducerApplyFrom;
import com.fortify.cli.common.log.LogSensitivityLevel;
import com.fortify.cli.common.log.MaskValue;
import com.fortify.cli.common.output.cli.cmd.AbstractOutputCommand;
import com.fortify.cli.common.output.cli.cmd.IJsonNodeSupplier;
import com.fortify.cli.common.output.cli.mixin.OutputHelperMixins;
import com.fortify.cli.common.progress.cli.mixin.ProgressWriterFactoryMixin;
import com.fortify.cli.common.progress.helper.IProgressWriterI18n;

import lombok.Getter;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

@Command(name = "diagnose")
public class AviatorDiagnoseCommand extends AbstractOutputCommand implements IJsonNodeSupplier {
    @Getter @Mixin private OutputHelperMixins.TableNoQuery outputHelper;
    @Mixin private ProgressWriterFactoryMixin progressWriterFactoryMixin;
    @ArgGroup(exclusive = true, multiplicity = "1", order = 1)
    private AviatorTargetArgGroup targetOptions = new AviatorTargetArgGroup();
    @Option(names = {"--timeout"}, defaultValue = "10", order = 3)
    private long timeoutSeconds;
    @Option(names = {"--export"}, order = 4)
    private Path exportFile;

    private AviatorGrpcDiagnosticReport diagnosticResult;

    @Override
    public Integer call() {
        try (IProgressWriterI18n progressWriter = progressWriterFactoryMixin.create()) {
            progressWriter.writeI18nProgress("fcli.aviator.diagnose.progress.running", getAviatorUrl());
            AviatorGrpcDiagnosticReport result = getDiagnosticResult(progressWriter::writeProgress);
            AviatorGrpcDiagnosticVerdict verdict = result.verdict();
            getOutputHelper().write(simpleObjectNodeProducerBuilder(ObjectNodeProducerApplyFrom.SPEC).source(result.steps()).build());
            exportDiagnosticIfRequested(result, verdict, progressWriter);
            writeVerdict(verdict);
            if ( verdict.severity() == Severity.FAILED ) {
                progressWriter.writeI18nWarning("fcli.aviator.diagnose.progress.failed");
                return 1;
            }
            if ( verdict.severity() == Severity.WARN ) {
                progressWriter.writeI18nWarning("fcli.aviator.diagnose.progress.warning");
                return 0;
            }
            progressWriter.writeI18nProgress("fcli.aviator.diagnose.progress.succeeded");
            return 0;
        }
    }

    @Override
    public JsonNode getJsonNode() {
        return getDiagnosticResult(null).toJson();
    }

    @Override
    public boolean isSingular() {
        return false;
    }

    private AviatorGrpcDiagnosticReport getDiagnosticResult(Consumer<String> progressConsumer) {
        if ( diagnosticResult == null ) {
            validateOptions();
            diagnosticResult = AviatorGrpcConnectivityDiagnosticHelper.runDiagnostic(getAviatorUrl(), timeoutSeconds, progressConsumer);
        }
        return diagnosticResult;
    }

    private void validateOptions() {
        if ( timeoutSeconds <= 0 ) {
            throw new AviatorSimpleException("--timeout must be greater than 0");
        }
    }

    private String getAviatorUrl() {
        return targetOptions.getAviatorUrl();
    }

    private String getTargetSource() {
        return targetOptions.hasUrlOption() ? "url" : "session";
    }

    private void exportDiagnosticIfRequested(AviatorGrpcDiagnosticReport result, AviatorGrpcDiagnosticVerdict verdict,
            IProgressWriterI18n progressWriter) {
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
            exportNode.put("targetSource", getTargetSource());
            if ( targetOptions.hasSessionOption() ) {
                exportNode.put("aviatorSession", targetOptions.getSessionName());
            }
            exportNode.put("timeoutSeconds", timeoutSeconds);
            exportNode.put("connectivityFailure", result.connectivityFailure());
            exportNode.set("verdict", verdict.asJson());
            exportNode.set("steps", result.toJson());

            JsonHelper.getObjectMapper().writerWithDefaultPrettyPrinter().writeValue(absolutePath.toFile(), exportNode);
            progressWriter.writeI18nProgress("fcli.aviator.diagnose.progress.exported", absolutePath);
        } catch ( IOException e ) {
            throw new AviatorSimpleException("Unable to export diagnostic bundle: " + e.getMessage(), e);
        }
    }

    private void writeVerdict(AviatorGrpcDiagnosticVerdict verdict) {
        var err = getCommandHelper().getRootCommandLine().getErr();
        err.println(verdict.toDisplayString());
        err.flush();
    }

    private static final class AviatorTargetArgGroup {
        @Option(names = {"--url"}, order = 1)
        @MaskValue(sensitivity = LogSensitivityLevel.low, description = "AVIATOR HOST NAME", pattern = MaskValue.URL_HOSTNAME_PATTERN)
        private String aviatorUrl;
        @Option(names = {"--aviator-session", "--av-session"}, order = 2)
        private String sessionName;

        private boolean hasUrlOption() {
            return StringUtils.isNotBlank(aviatorUrl);
        }

        private boolean hasSessionOption() {
            return StringUtils.isNotBlank(sessionName);
        }

        private String getAviatorUrl() {
            return hasUrlOption() ? aviatorUrl : getSessionDescriptor().getAviatorUrl();
        }

        private AviatorUserSessionDescriptor getSessionDescriptor() {
            return AviatorUserSessionHelper.instance().get(getSessionName(), true);
        }

        private String getSessionName() {
            return sessionName;
        }
    }

}