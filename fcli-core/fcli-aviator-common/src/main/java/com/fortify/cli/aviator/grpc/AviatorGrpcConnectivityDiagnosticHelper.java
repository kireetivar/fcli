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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fortify.cli.aviator._common.exception.AviatorSimpleException;
import com.fortify.cli.aviator.grpc.AviatorGrpcDiagnosticReport.DiagnosticStatus;
import com.fortify.cli.aviator.grpc.AviatorGrpcDiagnosticReport.StepName;
import com.fortify.cli.common.json.JsonHelper;
import com.fortify.grpc.token.TokenServiceGrpc;
import com.fortify.grpc.token.TokenValidationResponse;
import com.fortify.grpc.token.ValidateUserTokenRequest;

import io.grpc.ConnectivityState;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import lombok.extern.slf4j.Slf4j;

/**
 * Client-side Aviator connectivity diagnostics that separate endpoint validation,
 * DNS, TCP, TLS/ALPN, gRPC channel readiness, and gRPC request/response
 * reachability into distinct ordered steps.
 */
@Slf4j
public final class AviatorGrpcConnectivityDiagnosticHelper {
    private static final String ACTION_CONFIGURE_TRUSTSTORE =
        "Run 'fcli config truststore set' to configure a custom truststore";
    private static final String ACTION_VERIFY_DNS =
        "Verify the Aviator hostname and DNS resolution on this machine";
    private static final String ACTION_VERIFY_SERVICE_PORT =
        "Verify the Aviator gRPC service is reachable on the configured host and port";
    private static final String ACTION_VERIFY_GRPC_ROUTE =
        "Check VPN, firewall, proxy, load balancer, or CDN settings for gRPC and HTTP/2 traffic";
    private static final String ACTION_VERIFY_AVIATOR_ENDPOINT =
        "Verify the URL points to the Aviator gRPC endpoint and not another HTTPS or gRPC service";
    // Conservative client-side thresholds for flagging unexpectedly slow connectivity steps.
    private static final long DNS_LATENCY_WARNING_MS = 5000;
    private static final long TCP_LATENCY_WARNING_MS = 2000;
    private static final long TLS_LATENCY_WARNING_MS = 3000;
    private static final long GRPC_LATENCY_WARNING_MS = 10000;

    private AviatorGrpcConnectivityDiagnosticHelper() {}

    public static ArrayNode diagnose(String aviatorUrl, long timeoutSeconds) {
        return runDiagnostic(aviatorUrl, timeoutSeconds, null).toJson();
    }

    public static AviatorGrpcDiagnosticReport runDiagnostic(String aviatorUrl, long timeoutSeconds, Consumer<String> progressConsumer) {
        ArrayNode result = JsonHelper.getObjectMapper().createArrayNode();
        Duration timeout = Duration.ofSeconds(Math.max(1, timeoutSeconds));
        AviatorGrpcClientHelper.AviatorGrpcTarget target = AviatorGrpcClientHelper.parseTarget(aviatorUrl);

        log.debug("Starting Aviator connectivity diagnostic for host={} port={} timeoutSeconds={}",
            target.host(), target.port(), timeoutSeconds);

        ObjectNode targetStep = createTargetStep(target);
        result.add(targetStep);
        logStepOutcome(targetStep);

        ObjectNode environmentStep = AviatorGrpcDiagnosticEnvironmentHelper.createEnvironmentStep(target);
        result.add(environmentStep);
        logStepOutcome(environmentStep);
        String jvmProxySummary = environmentStep.path("jvmProxySummary").asText("direct");
        boolean directJvmPath = AviatorGrpcDiagnosticEnvironmentHelper.isDirectJvmProxySummary(jvmProxySummary);
        String proxySkipSummary = getRawSocketProxySkipSummary(jvmProxySummary);
        String dnsProgressMessage = directJvmPath
                ? "Resolving host %s"
                : "Skipping local DNS because JVM proxy selection is %s";
        Object dnsProgressArg = directJvmPath ? target.host() : jvmProxySummary;

        StepOutcome dnsOutcome = addStep(result, progressConsumer,
                () -> probeDnsOrSkip(target, timeout, directJvmPath, jvmProxySummary),
                dnsProgressMessage,
                dnsProgressArg);

        List<String> resolvedAddresses = directJvmPath && dnsOutcome.allowsDependentSteps()
            ? getResolvedAddresses(dnsOutcome.node())
            : List.of();
        String primaryResolvedAddress = directJvmPath && dnsOutcome.allowsDependentSteps()
            ? getPrimaryResolvedAddress(target, resolvedAddresses)
            : null;
        String grpcProbePath = StringUtils.defaultIfBlank(primaryResolvedAddress, target.host());
        String directProbePath = StringUtils.defaultIfBlank(primaryResolvedAddress, target.host());
        String tcpProgressMessage = getTcpProgressMessage(directJvmPath, dnsOutcome.allowsDependentSteps());

        StepOutcome tcpOutcome = addStep(result, progressConsumer,
                () -> probeTcpOrSkip(target, primaryResolvedAddress, timeout, directJvmPath,
                dnsOutcome.allowsDependentSteps(), proxySkipSummary),
                tcpProgressMessage,
                directJvmPath ? target.host() : jvmProxySummary,
                target.port(),
                directProbePath);
        String tlsProgressMessage = getTlsProgressMessage(directJvmPath, tcpOutcome);

        StepOutcome tlsOutcome = addStep(result, progressConsumer,
                () -> probeTlsAndAlpnOrSkip(target, primaryResolvedAddress, timeout, directJvmPath, tcpOutcome, proxySkipSummary),
                tlsProgressMessage,
                directJvmPath ? target.host() : jvmProxySummary,
                target.port(),
                directProbePath);
        boolean grpcTransportProbeAllowed = !directJvmPath || tlsOutcome.allowsDependentSteps();

        StepOutcome grpcChannelOutcome = addStep(result, progressConsumer,
            () -> grpcTransportProbeAllowed
                ? probeGrpcChannel(target, primaryResolvedAddress, timeout)
                : skippedStep(target, StepName.GRPC_CHANNEL, "Skipped because TLS or ALPN probe failed"),
            grpcTransportProbeAllowed
                ? "Waiting for gRPC channel readiness via %s"
                : "Skipping gRPC channel check because TLS or ALPN failed",
            grpcProbePath);
        AviatorGrpcDiagnosticActionHelper.addTrustStoreContextIfApplicable(grpcChannelOutcome.node(), environmentStep);

        addStep(result, progressConsumer,
            () -> grpcChannelOutcome.allowsDependentSteps()
                ? probeGrpcResponse(target, primaryResolvedAddress, timeout)
                : skippedStep(target, StepName.GRPC_RESPONSE,
                        "Skipped because the gRPC channel did not reach READY state"),
            grpcChannelOutcome.allowsDependentSteps()
                ? "Sending a gRPC connectivity probe and waiting for a response via %s"
                : "Skipping gRPC response check because the gRPC channel did not reach READY state",
            grpcProbePath);

        boolean connectivityFailure = hasConnectivityFailure(result);
        log.debug("Completed Aviator connectivity diagnostic for host={} port={} connectivityFailure={}",
                target.host(), target.port(), connectivityFailure);
        return new AviatorGrpcDiagnosticReport(result, connectivityFailure);
    }

    private static StepOutcome addStep(ArrayNode result, Consumer<String> progressConsumer, Supplier<StepOutcome> supplier,
            String progressMessage, Object... args) {
        writeProgress(progressConsumer, progressMessage, args);
        StepOutcome outcome = supplier.get();
        result.add(outcome.node());
        logStepOutcome(outcome.node());
        return outcome;
    }

    private static void writeProgress(Consumer<String> progressConsumer, String progressMessage, Object... args) {
        if ( progressConsumer != null ) {
            progressConsumer.accept(String.format(Locale.ROOT, progressMessage, args));
        }
    }

    private static StepOutcome probeDnsOrSkip(AviatorGrpcClientHelper.AviatorGrpcTarget target, Duration timeout,
            boolean directJvmPath, String jvmProxySummary) {
        if ( directJvmPath ) {
            return probeDns(target, timeout);
        }
        return skippedStep(target, StepName.DNS, String.format(Locale.ROOT,
                "Skipped because JVM proxy selection is %s; local DNS would not model proxied gRPC traffic",
                jvmProxySummary));
    }

    private static StepOutcome probeTcpOrSkip(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress, Duration timeout,
            boolean directJvmPath, boolean dnsSucceeded, String proxySkipSummary) {
        if ( !directJvmPath ) {
            return skippedStep(target, StepName.TCP, proxySkipSummary);
        }
        if ( !dnsSucceeded ) {
            return skippedStep(target, StepName.TCP, "Skipped because DNS resolution failed");
        }
        return probeTcp(target, resolvedAddress, timeout);
    }

    private static StepOutcome probeTlsAndAlpnOrSkip(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress,
            Duration timeout, boolean directJvmPath, StepOutcome tcpOutcome, String proxySkipSummary) {
        if ( !directJvmPath ) {
            return skippedStep(target, StepName.TLS_ALPN, proxySkipSummary);
        }
        if ( !tcpOutcome.allowsDependentSteps() ) {
            return skippedStep(target, StepName.TLS_ALPN, "Skipped because TCP connect failed");
        }
        return probeTlsAndAlpn(target, resolvedAddress, timeout);
    }

    private static String getTcpProgressMessage(boolean directJvmPath, boolean dnsSucceeded) {
        if ( !directJvmPath ) {
            return "Skipping TCP connect because JVM proxy selection is %s";
        }
        if ( !dnsSucceeded ) {
            return "Skipping TCP connect because DNS resolution failed";
        }
        return "Connecting to %s:%d via %s";
    }

    private static String getTlsProgressMessage(boolean directJvmPath, StepOutcome tcpOutcome) {
        if ( !directJvmPath ) {
            return "Skipping TLS and ALPN because JVM proxy selection is %s";
        }
        return tcpOutcome.allowsDependentSteps()
                ? "Negotiating TLS and ALPN with %s:%d via %s"
                : "Skipping TLS and ALPN because TCP connect failed";
    }

    private static String getRawSocketProxySkipSummary(String jvmProxySummary) {
        return String.format(Locale.ROOT,
                "Skipped because JVM proxy selection is %s; the raw socket probe would not model proxied gRPC traffic",
                jvmProxySummary);
    }

    private static void logStepOutcome(ObjectNode step) {
        if ( log.isDebugEnabled() ) {
            log.debug("Aviator diagnose step={} status={} durationMs={} summary={} failureCategory={}",
                    step.path("step").asText(),
                    step.path("status").asText(),
                    step.path("durationMs").asLong(),
                    step.path("summary").asText(),
                    step.path("failureCategory").asText(""));
        }
    }

    private static boolean hasConnectivityFailure(ArrayNode steps) {
        for ( JsonNode step : steps ) {
            if ( isConnectivityFailureStep(step) ) {
                return true;
            }
        }
        return false;
    }

    public static boolean isConnectivityFailureStep(JsonNode step) {
        if ( step == null || !DiagnosticStatus.FAILED.name().equals(step.path("status").asText()) ) {
            return false;
        }
        return isConnectivityStep(step.path("step").asText());
    }

    public static boolean isConnectivityStep(String stepName) {
        StepName diagnosticStepName = StepName.fromText(stepName);
        return diagnosticStepName != null && diagnosticStepName.isConnectivityStep();
    }

    private static ObjectNode createTargetStep(AviatorGrpcClientHelper.AviatorGrpcTarget target) {
        ObjectNode step = baseStep(target, StepName.TARGET);
        step.put("status", DiagnosticStatus.OK.name());
        step.put("durationMs", 0);
        step.put("summary", String.format(Locale.ROOT, "Using %s:%d", target.host(), target.port()));
        step.put("explicitPort", target.explicitPort());
        return step;
    }

    private static StepOutcome probeDns(AviatorGrpcClientHelper.AviatorGrpcTarget target, Duration timeout) {
        Instant start = Instant.now();
        try {
            List<String> addresses = runWithTimeout(timeout, () -> resolveDistinctAddresses(target.host()));
            ObjectNode step = okStep(target, StepName.DNS, start,
                    String.format(Locale.ROOT, "Resolved %d address(es)", addresses.size()));
            ArrayNode values = step.putArray("addresses");
            addresses.forEach(values::add);
            step.put("details", String.join(", ", addresses));
            return StepOutcome.success(step);
        } catch (TimeoutException e) {
            ObjectNode step = failedStep(target, StepName.DNS, start,
                    String.format(Locale.ROOT, "Timed out resolving %s", target.host()),
                    new FailureInfo("dns_timeout", ACTION_VERIFY_DNS));
            step.put("details", String.format(Locale.ROOT, "DNS resolution exceeded timeout of %d ms", timeout.toMillis()));
            return StepOutcome.failure(step);
        } catch (Exception e) {
            return StepOutcome.failure(errorStep(target, StepName.DNS, start, e,
                    String.format(Locale.ROOT, "Could not resolve %s", target.host()),
                    new FailureInfo("dns_resolution_failed", ACTION_VERIFY_DNS)));
        }
    }

    private static StepOutcome probeTcp(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress, Duration timeout) {
        Instant start = Instant.now();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(resolvedAddress, target.port()), Math.toIntExact(timeout.toMillis()));
            ObjectNode step = okStep(target, StepName.TCP, start,
                    String.format(Locale.ROOT, "Connected to %s:%d via %s", target.host(), target.port(), resolvedAddress));
            step.put("resolvedAddress", resolvedAddress);
            step.put("remoteAddress", socket.getRemoteSocketAddress().toString());
            return StepOutcome.success(step);
        } catch (Exception e) {
            return StepOutcome.failure(errorStep(target, StepName.TCP, start, e,
                    String.format(Locale.ROOT, "Could not connect to %s:%d via %s", target.host(), target.port(), resolvedAddress),
                    tcpFailureInfo(e)));
        }
    }

    private static StepOutcome probeTlsAndAlpn(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress, Duration timeout) {
        Instant start = Instant.now();
        try (Socket plainSocket = new Socket()) {
            plainSocket.connect(new InetSocketAddress(resolvedAddress, target.port()), Math.toIntExact(timeout.toMillis()));
            plainSocket.setSoTimeout(Math.toIntExact(timeout.toMillis()));
            try (SSLSocket socket = (SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault())
                    .createSocket(plainSocket, target.host(), target.port(), true)) {
                socket.setSoTimeout(Math.toIntExact(timeout.toMillis()));
                socket.setSSLParameters(createTlsProbeSslParameters(socket.getSSLParameters()));
                socket.startHandshake();

                SSLSession session = socket.getSession();
                String negotiatedProtocol = socket.getApplicationProtocol();
                if (!"h2".equals(negotiatedProtocol)) {
                    ObjectNode step = failedStep(target, StepName.TLS_ALPN, start,
                            "TLS handshake succeeded, but ALPN did not negotiate h2",
                            new FailureInfo("tls_alpn_missing", ACTION_VERIFY_GRPC_ROUTE));
                    step.put("resolvedAddress", resolvedAddress);
                    step.put("remoteAddress", plainSocket.getRemoteSocketAddress().toString());
                    step.put("negotiatedProtocol", negotiatedProtocol == null || negotiatedProtocol.isBlank() ? "<none>" : negotiatedProtocol);
                    step.put("tlsProtocol", session.getProtocol());
                    step.put("cipherSuite", session.getCipherSuite());
                    addCertificateDetails(step, session);
                    return StepOutcome.failure(step);
                }

                ObjectNode step = okStep(target, StepName.TLS_ALPN, start,
                    "TLS handshake succeeded and ALPN negotiated h2");
                step.put("resolvedAddress", resolvedAddress);
                step.put("remoteAddress", plainSocket.getRemoteSocketAddress().toString());
                step.put("negotiatedProtocol", negotiatedProtocol);
                step.put("tlsProtocol", session.getProtocol());
                step.put("cipherSuite", session.getCipherSuite());
                addCertificateDetails(step, session);
                return StepOutcome.success(step);
            }
        } catch (Exception e) {
            return StepOutcome.failure(errorStep(target, StepName.TLS_ALPN, start, e,
                    String.format(Locale.ROOT, "TLS handshake failed for %s:%d via %s", target.host(), target.port(), resolvedAddress),
                    tlsFailureInfo(e)));
        }
    }

    private static StepOutcome probeGrpcChannel(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress, Duration timeout) {
        Instant start = Instant.now();
        ManagedChannel channel = AviatorGrpcClientHelper.createChannel(target.originalUrl(), resolvedAddress);
        try {
            GrpcChannelProbeState probeState = waitForGrpcChannelState(channel, start, timeout);
            if ( probeState.isReady() ) {
                return StepOutcome.success(createGrpcChannelSuccessStep(target, resolvedAddress, start, probeState));
            }
            return StepOutcome.failure(createGrpcChannelFailureStep(target, resolvedAddress, start, probeState));
        } catch (Exception e) {
            ObjectNode step = errorStep(target, StepName.GRPC_CHANNEL, start, e,
                    "gRPC channel could not be established",
                    grpcTransportFailureInfo(describeException(e), new FailureInfo("grpc_channel_error", ACTION_VERIFY_GRPC_ROUTE)));
            putResolvedAddress(step, resolvedAddress);
            return StepOutcome.failure(step);
        } finally {
            shutdownChannel(channel);
        }
    }

    private static GrpcChannelProbeState waitForGrpcChannelState(ManagedChannel channel, Instant start, Duration timeout)
            throws InterruptedException {
        GrpcChannelProbeState probeState = new GrpcChannelProbeState(channel.getState(true), start);
        Instant deadline = start.plus(timeout);
        while ( Instant.now().isBefore(deadline) && !probeState.isReady() && !probeState.isShutdown() ) {
            CountDownLatch latch = new CountDownLatch(1);
            channel.notifyWhenStateChanged(probeState.state(), latch::countDown);
            long remainingMillis = Duration.between(Instant.now(), deadline).toMillis();
            if ( remainingMillis <= 0 || !latch.await(remainingMillis, TimeUnit.MILLISECONDS) ) {
                break;
            }
            probeState.transitionTo(channel.getState(false), start);
        }
        return probeState;
    }

    private static ObjectNode createGrpcChannelSuccessStep(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress,
            Instant start, GrpcChannelProbeState probeState) {
        String summary = probeState.sawTransientFailure()
                ? "Channel reached READY after recovering from TRANSIENT_FAILURE"
                : "Channel reached READY state";
        ObjectNode step = okStep(target, StepName.GRPC_CHANNEL, start, summary);
        putResolvedAddress(step, resolvedAddress);
        addGrpcChannelProbeDetails(step, probeState);
        if ( probeState.sawTransientFailure() ) {
            step.put("details", "The channel temporarily entered TRANSIENT_FAILURE but recovered on retry (normal with multiple backends).");
        }
        return step;
    }

    private static ObjectNode createGrpcChannelFailureStep(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress,
            Instant start, GrpcChannelProbeState probeState) {
        String summary = probeState.isShutdown()
                ? "Channel entered SHUTDOWN before READY"
                : buildGrpcChannelTimeoutSummary(probeState.state());
        ObjectNode step = failedStep(target, StepName.GRPC_CHANNEL, start, summary,
            grpcChannelFailureInfo(probeState.state()));
        putResolvedAddress(step, resolvedAddress);
        step.put("details", describeConnectivityState(probeState.state()));
        addGrpcChannelProbeDetails(step, probeState);
        return step;
    }

    private static void addGrpcChannelProbeDetails(ObjectNode step, GrpcChannelProbeState probeState) {
        step.put("connectivityState", probeState.state().name());
        step.set("stateTransitions", probeState.stateTransitions());
        step.put("transientFailureCount", probeState.transientFailureCount());
        step.put("retryCyclesObserved", probeState.retryCyclesObserved());
    }

    private static StepOutcome probeGrpcResponse(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress, Duration timeout) {
        Instant start = Instant.now();
        ManagedChannel channel = AviatorGrpcClientHelper.createChannel(target.originalUrl(), resolvedAddress);
        try {
            TokenServiceGrpc.TokenServiceBlockingStub stub = TokenServiceGrpc.newBlockingStub(channel)
                    .withWaitForReady()
                    .withDeadlineAfter(timeout.toSeconds(), TimeUnit.SECONDS);
            TokenValidationResponse response = stub.validateUserToken(ValidateUserTokenRequest.newBuilder()
                    .setToken("")
                    .setTenantName("")
                    .build());

            ObjectNode step = okStep(target, StepName.GRPC_RESPONSE, start, buildGrpcResponseSummary(response));
            putResolvedAddress(step, resolvedAddress);
            if ( StringUtils.isNotBlank(response.getErrorMessage()) ) {
                step.put("details", response.getErrorMessage());
            }
            return StepOutcome.success(step);
        } catch (StatusRuntimeException e) {
            return classifyGrpcResponseException(target, resolvedAddress, start, e);
        } catch (Exception e) {
            ObjectNode step = errorStep(target, StepName.GRPC_RESPONSE, start, e,
                    "The gRPC connectivity probe could not be completed",
                    new FailureInfo("grpc_response_failed", ACTION_VERIFY_GRPC_ROUTE));
            putResolvedAddress(step, resolvedAddress);
            return StepOutcome.failure(step);
        } finally {
            shutdownChannel(channel);
        }
    }

    private static StepOutcome skippedStep(AviatorGrpcClientHelper.AviatorGrpcTarget target,
            StepName stepName, String summary) {
        ObjectNode step = baseStep(target, stepName);
        step.put("status", DiagnosticStatus.SKIPPED.name());
        step.put("durationMs", 0);
        step.put("summary", summary);
        return StepOutcome.skipped(step);
    }

    private static ObjectNode okStep(AviatorGrpcClientHelper.AviatorGrpcTarget target, StepName stepName,
            Instant start, String summary) {
        ObjectNode step = baseStep(target, stepName);
        step.put("status", DiagnosticStatus.OK.name());
        step.put("durationMs", elapsedMillis(start));
        step.put("summary", summary);
        applyLatencyInfo(step);
        return step;
    }

        private static ObjectNode failedStep(AviatorGrpcClientHelper.AviatorGrpcTarget target, StepName stepName,
            Instant start, String summary, FailureInfo failureInfo) {
        ObjectNode step = baseStep(target, stepName);
        step.put("status", DiagnosticStatus.FAILED.name());
        step.put("durationMs", elapsedMillis(start));
        step.put("summary", summary);
        addFailureInfo(step, failureInfo);
        applyLatencyInfo(step);
        return step;
    }

        private static ObjectNode errorStep(AviatorGrpcClientHelper.AviatorGrpcTarget target, StepName stepName,
            Instant start, Exception exception, String summary, FailureInfo failureInfo) {
        ObjectNode step = failedStep(target, stepName, start, summary, failureInfo);
        step.put("errorType", exception.getClass().getSimpleName());
        step.put("details", describeException(exception));
        log.debug("Aviator diagnose step {} failed", stepName, exception);
        return step;
    }

    private static void addFailureInfo(ObjectNode step, FailureInfo failureInfo) {
        if ( failureInfo != null ) {
            step.put("failureCategory", failureInfo.category());
            step.put("recommendedAction", failureInfo.recommendedAction());
            step.put("hint", failureInfo.recommendedAction());
        }
    }

    private static ObjectNode baseStep(AviatorGrpcClientHelper.AviatorGrpcTarget target, StepName stepName) {
        ObjectNode step = JsonHelper.getObjectMapper().createObjectNode();
        step.put("step", stepName.text());
        step.put("host", target.host());
        step.put("port", target.port());
        step.put("target", String.format(Locale.ROOT, "%s:%d", target.host(), target.port()));
        return step;
    }

    private static long elapsedMillis(Instant start) {
        return Duration.between(start, Instant.now()).toMillis();
    }

    private static String describeException(Exception exception) {
        if (exception instanceof SocketTimeoutException) {
            return "Connection timed out";
        }
        if (exception instanceof AviatorSimpleException) {
            return exception.getMessage();
        }
        if (exception instanceof IOException) {
            return exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage();
        }
        if (exception instanceof InterruptedException) {
            Thread.currentThread().interrupt();
            return "Interrupted while waiting for network operation";
        }
        return exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage();
    }

    private static String describeConnectivityState(ConnectivityState state) {
        return switch (state) {
            case IDLE -> "The channel is idle and has not established an active transport.";
            case CONNECTING -> "The channel is still trying to establish the gRPC transport.";
            case READY -> "The channel established a working gRPC transport.";
            case TRANSIENT_FAILURE -> "The endpoint accepted earlier network steps, but the gRPC transport failed or was closed before becoming ready; behind a load balancer or proxy, this often means HTTP/2 or backend forwarding is not completing successfully.";
            case SHUTDOWN -> "The channel shut down before a working gRPC transport was established.";
        };
    }

    static String buildGrpcChannelTimeoutSummary(ConnectivityState state) {
        return switch ( state ) {
            case TRANSIENT_FAILURE -> "TLS succeeded, but the gRPC channel never became READY and remained in TRANSIENT_FAILURE; this often indicates that a VPN, firewall, proxy, load balancer, or backend gRPC listener accepted the connection but did not complete end-to-end HTTP/2 gRPC handling";
            default -> String.format(Locale.ROOT, "Timed out waiting for READY; last state was %s", state.name());
        };
    }

    static String buildGrpcResponseSummary(TokenValidationResponse response) {
        if ( response.getValid() ) {
            return "Received a gRPC application response to the connectivity probe; the service unexpectedly accepted the empty probe token";
        }
        String errorMessage = response.getErrorMessage();
        if (errorMessage == null || errorMessage.isBlank()) {
            return "Received a gRPC application response to the connectivity probe";
        }
        if ( isExpectedProbeTokenRejection(errorMessage) ) {
            return "Received a gRPC application response to the connectivity probe; Aviator rejected the expected empty probe token, which confirms end-to-end gRPC reachability";
        }
        return "Received a gRPC application response to the connectivity probe; the service returned an application-level rejection, which still confirms end-to-end gRPC reachability";
    }

    private static boolean isExpectedProbeTokenRejection(String errorMessage) {
        String normalized = lowerCaseOrEmpty(errorMessage);
        return normalized.contains("token validation failed")
                || normalized.contains("invalid token")
                || normalized.contains("expired token")
                || normalized.contains("unauth");
    }

    private static StepOutcome classifyGrpcResponseException(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress,
            Instant start,
            StatusRuntimeException exception) {
        String statusName = exception.getStatus().getCode().name();
        String description = exception.getStatus().getDescription() == null ? "No additional server details" : exception.getStatus().getDescription();
        boolean serviceReached = isGrpcProbeSuccessStatus(exception.getStatus().getCode());
        boolean rpcImplemented = exception.getStatus().getCode() != Status.Code.UNIMPLEMENTED;
        DiagnosticStatus status = DiagnosticStatus.FAILED;
        if ( serviceReached ) {
            status = rpcImplemented ? DiagnosticStatus.OK : DiagnosticStatus.WARN;
        }

        boolean isCertError = isCertificateError(description);
        FailureInfo failureInfo = serviceReached ? null : grpcProbeFailureInfo(exception, isCertError);

        ObjectNode step = baseStep(target, StepName.GRPC_RESPONSE);
        step.put("status", status.name());
        step.put("durationMs", elapsedMillis(start));
        putResolvedAddress(step, resolvedAddress);
        step.put("grpcStatus", statusName);
        step.put("details", description);
        addFailureInfo(step, failureInfo);
        if ( exception.getStatus().getCode() == Status.Code.UNIMPLEMENTED ) {
            step.put("recommendedAction", ACTION_VERIFY_AVIATOR_ENDPOINT);
            step.put("hint", ACTION_VERIFY_AVIATOR_ENDPOINT);
        }
        step.put("summary", buildGrpcResponseExceptionSummary(exception, statusName, serviceReached, isCertError));
        return serviceReached ? StepOutcome.success(step) : StepOutcome.failure(step);
    }

    private static String buildGrpcResponseExceptionSummary(StatusRuntimeException exception, String statusName, boolean serviceReached,
            boolean certificateError) {
        if ( exception.getStatus().getCode() == Status.Code.DEADLINE_EXCEEDED ) {
            return "TLS and gRPC transport were established, but the probe RPC did not receive a response before timeout; verify proxy or upstream response-path handling for gRPC over HTTP/2";
        }
        if ( serviceReached ) {
            return exception.getStatus().getCode() == Status.Code.UNIMPLEMENTED
                    ? "Received a gRPC response, but the connectivity probe RPC is not implemented there; this may be an older Aviator server or a different gRPC service"
                    : String.format(Locale.ROOT, "Received a gRPC application response with status %s", statusName);
        }
        if ( certificateError ) {
            return String.format(Locale.ROOT, "The gRPC connectivity probe failed with %s because the server certificate is not trusted", statusName);
        }
        return String.format(Locale.ROOT, "The gRPC connectivity probe failed with %s", statusName);
    }

    private static void addCertificateDetails(ObjectNode step, SSLSession session) {
        try {
            addCertificateDetails(step, session.getPeerCertificates());
        } catch (Exception e) {
            log.debug("Unable to inspect peer certificates for Aviator diagnostic", e);
        }
    }

    static void addCertificateDetails(ObjectNode step, Certificate[] peerCertificates) {
        step.put("certificateChainLength", peerCertificates.length);
        ArrayNode certificateNodes = step.putArray("peerCertificates");
        for ( Certificate peerCertificate : peerCertificates ) {
            if ( peerCertificate instanceof X509Certificate x509Certificate ) {
                ObjectNode certificateNode = certificateNodes.addObject();
                String subject = x509Certificate.getSubjectX500Principal().getName();
                String issuer = x509Certificate.getIssuerX500Principal().getName();
                boolean selfSigned = x509Certificate.getSubjectX500Principal().equals(x509Certificate.getIssuerX500Principal());
                certificateNode.put("subject", subject);
                certificateNode.put("issuer", issuer);
                certificateNode.put("notBefore", x509Certificate.getNotBefore().toInstant().toString());
                certificateNode.put("notAfter", x509Certificate.getNotAfter().toInstant().toString());
                certificateNode.put("selfSigned", selfSigned);
                if ( !step.has("certSubject") ) {
                    step.put("certSubject", subject);
                    step.put("certIssuer", issuer);
                    step.put("certExpiry", x509Certificate.getNotAfter().toInstant().toString());
                    step.put("certSelfSigned", selfSigned);
                }
            }
        }
    }

    private static boolean isCertificateError(String description) {
        String normalizedDescription = lowerCaseOrEmpty(description);
        return normalizedDescription.contains("pkix path")
                || normalizedDescription.contains("certification path")
                || normalizedDescription.contains("certificate")
                || normalizedDescription.contains("trust anchor");
    }

    private static FailureInfo tcpFailureInfo(Exception exception) {
        if ( exception instanceof SocketTimeoutException ) {
            return new FailureInfo("tcp_timeout", ACTION_VERIFY_SERVICE_PORT);
        }
        String description = describeException(exception).toLowerCase(Locale.ROOT);
        if ( description.contains("refused") ) {
            return new FailureInfo("tcp_connection_refused", ACTION_VERIFY_SERVICE_PORT);
        }
        return new FailureInfo("tcp_connection_failed", ACTION_VERIFY_SERVICE_PORT);
    }

    private static FailureInfo tlsFailureInfo(Exception exception) {
        String description = describeException(exception);
        if ( isCertificateError(description) ) {
            return new FailureInfo("tls_untrusted_cert", ACTION_CONFIGURE_TRUSTSTORE);
        }
        if ( exception instanceof SocketTimeoutException ) {
            return new FailureInfo("tls_handshake_timeout", ACTION_VERIFY_GRPC_ROUTE);
        }
        return new FailureInfo("tls_handshake_failed", ACTION_VERIFY_GRPC_ROUTE);
    }

    private static FailureInfo grpcChannelFailureInfo(ConnectivityState state) {
        return switch ( state ) {
            case IDLE, CONNECTING -> new FailureInfo("grpc_deadline_exceeded", ACTION_VERIFY_GRPC_ROUTE);
            case TRANSIENT_FAILURE -> new FailureInfo("grpc_transient_failure", ACTION_VERIFY_GRPC_ROUTE);
            case SHUTDOWN -> new FailureInfo("grpc_channel_shutdown", ACTION_VERIFY_GRPC_ROUTE);
            case READY -> null;
        };
    }

    static FailureInfo grpcProbeFailureInfo(StatusRuntimeException exception, boolean certificateError) {
        if ( certificateError ) {
            return new FailureInfo("tls_untrusted_cert", ACTION_CONFIGURE_TRUSTSTORE);
        }
        FailureInfo defaultInfo = switch ( exception.getStatus().getCode() ) {
            case DEADLINE_EXCEEDED -> new FailureInfo("grpc_deadline_exceeded", ACTION_VERIFY_GRPC_ROUTE);
            case UNAVAILABLE -> new FailureInfo("grpc_unavailable", ACTION_VERIFY_GRPC_ROUTE);
            default -> new FailureInfo("grpc_" + exception.getStatus().getCode().name().toLowerCase(Locale.ROOT), ACTION_VERIFY_GRPC_ROUTE);
        };
        return grpcTransportFailureInfo(exception.getStatus().getDescription(), defaultInfo);
    }

    static boolean isGrpcProbeSuccessStatus(Status.Code statusCode) {
        return switch ( statusCode ) {
            case INVALID_ARGUMENT, PERMISSION_DENIED, UNAUTHENTICATED, UNIMPLEMENTED -> true;
            default -> false;
        };
    }

    static FailureInfo grpcTransportFailureInfo(String description, FailureInfo defaultInfo) {
        String normalizedDescription = lowerCaseOrEmpty(description);
        if ( normalizedDescription.contains("goaway") ) {
            return new FailureInfo("grpc_goaway", ACTION_VERIFY_GRPC_ROUTE);
        }
        if ( normalizedDescription.contains("rst_stream") || normalizedDescription.contains("rst stream") ) {
            return new FailureInfo("grpc_rst_stream", ACTION_VERIFY_GRPC_ROUTE);
        }
        return defaultInfo;
    }

    private static String lowerCaseOrEmpty(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    private static void putResolvedAddress(ObjectNode step, String resolvedAddress) {
        if ( StringUtils.isNotBlank(resolvedAddress) ) {
            step.put("resolvedAddress", resolvedAddress);
        }
    }

    static SSLParameters createTlsProbeSslParameters(SSLParameters sslParameters) {
        sslParameters.setApplicationProtocols(new String[] {"h2", "http/1.1"});
        sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
        return sslParameters;
    }

    static <T> T runWithTimeout(Duration timeout, Callable<T> callable) throws Exception {
        ExecutorService executorService = newDaemonExecutor("aviator-dns-lookup");
        try {
            return runWithTimeout(executorService, timeout, callable);
        } finally {
            executorService.shutdownNow();
        }
    }

    static <T> T runWithTimeout(ExecutorService executorService, Duration timeout, Callable<T> callable) throws Exception {
        Future<T> future = executorService.submit(callable);
        try {
            return future.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw e;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if ( cause instanceof Exception exception ) {
                throw exception;
            }
            if ( cause instanceof Error error ) {
                throw error;
            }
            throw new RuntimeException(cause);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw e;
        }
    }

    private static ExecutorService newDaemonExecutor(String threadName) {
        return Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, threadName);
            thread.setDaemon(true);
            return thread;
        });
    }

    private static List<String> resolveDistinctAddresses(String host) throws IOException {
        return Arrays.stream(InetAddress.getAllByName(host))
                .map(InetAddress::getHostAddress)
                .distinct()
                .toList();
    }

    private static List<String> getResolvedAddresses(ObjectNode dnsNode) {
        JsonNode addressNode = dnsNode.path("addresses");
        if ( !addressNode.isArray() ) {
            return List.of();
        }
        return JsonHelper.stream((ArrayNode)addressNode).map(JsonNode::asText).toList();
    }

    static String getPrimaryResolvedAddress(AviatorGrpcClientHelper.AviatorGrpcTarget target, List<String> resolvedAddresses) {
        return resolvedAddresses.isEmpty() ? target.host() : resolvedAddresses.get(0);
    }

    private static void applyLatencyInfo(ObjectNode step) {
        String stepName = step.path("step").asText();
        long durationMs = step.path("durationMs").asLong(-1);
        long thresholdMs = getLatencyThreshold(stepName);
        if ( thresholdMs <= 0 || durationMs < 0 || durationMs <= thresholdMs ) {
            return;
        }
        step.put("latencyWarning", true);
        step.put("latencyThresholdMs", thresholdMs);
        String summary = step.path("summary").asText();
        step.put("summary", summary + String.format(Locale.ROOT, " (slow: %d ms > %d ms)", durationMs, thresholdMs));
        if ( DiagnosticStatus.OK.name().equals(step.path("status").asText()) ) {
            step.put("status", DiagnosticStatus.WARN.name());
        }
    }

    private static long getLatencyThreshold(String stepName) {
        StepName diagnosticStepName = StepName.fromText(stepName);
        if ( diagnosticStepName == null ) {
            return -1;
        }
        return switch ( diagnosticStepName ) {
            case DNS -> DNS_LATENCY_WARNING_MS;
            case TCP -> TCP_LATENCY_WARNING_MS;
            case TLS_ALPN -> TLS_LATENCY_WARNING_MS;
            case GRPC_CHANNEL, GRPC_RESPONSE -> GRPC_LATENCY_WARNING_MS;
            default -> -1;
        };
    }

    private static void shutdownChannel(ManagedChannel channel) {
        if (channel != null && !channel.isShutdown()) {
            channel.shutdownNow();
        }
    }

    static record FailureInfo(String category, String recommendedAction) {}

    private record StepOutcome(boolean allowsDependentSteps, ObjectNode node) {
        private static StepOutcome success(ObjectNode node) {
            return new StepOutcome(true, node);
        }

        private static StepOutcome failure(ObjectNode node) {
            return new StepOutcome(false, node);
        }

        private static StepOutcome skipped(ObjectNode node) {
            return new StepOutcome(false, node);
        }
    }
}