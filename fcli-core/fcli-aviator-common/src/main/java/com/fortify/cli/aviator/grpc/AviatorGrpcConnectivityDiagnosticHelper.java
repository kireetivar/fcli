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
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
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
import com.fortify.cli.common.http.proxy.helper.ProxyDescriptor;
import com.fortify.cli.common.http.proxy.helper.ProxyHelper;
import com.fortify.cli.common.http.ssl.truststore.helper.TrustStoreConfigDescriptor;
import com.fortify.cli.common.http.ssl.truststore.helper.TrustStoreConfigHelper;
import com.fortify.cli.common.json.JsonHelper;
import com.fortify.cli.common.util.EnvHelper;
import com.fortify.grpc.token.TokenServiceGrpc;
import com.fortify.grpc.token.TokenValidationResponse;
import com.fortify.grpc.token.ValidateUserTokenRequest;

import io.grpc.ConnectivityState;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import lombok.extern.slf4j.Slf4j;

/**
 * Client-side Aviator connectivity diagnostics that separate DNS, TCP, TLS/ALPN,
 * gRPC channel readiness, and optional token validation into distinct steps.
 */
@Slf4j
public final class AviatorGrpcConnectivityDiagnosticHelper {
    private static final String AVIATOR_MODULE = "aviator";
    private static final String ACTION_CONFIGURE_TRUSTSTORE =
        "Run 'fcli config truststore set' to configure a custom truststore";
    private static final String ACTION_VERIFY_DNS =
        "Verify the Aviator hostname and DNS resolution on this machine";
    private static final String ACTION_VERIFY_SERVICE_PORT =
        "Verify the Aviator gRPC service is reachable on the configured host and port";
    private static final String ACTION_VERIFY_GRPC_ROUTE =
        "Check firewall, proxy, load balancer, or CDN settings for gRPC and HTTP/2 traffic";
    private static final String ACTION_VERIFY_AVIATOR_ENDPOINT =
        "Verify the URL points to the Aviator gRPC endpoint and not another HTTPS or gRPC service";
    private static final String ACTION_RETRY_WITH_FRESH_TOKEN =
        "Generate a new Aviator user token and retry the command";
    private static final String ACTION_CHECK_BACKEND_HEALTH =
        "Check load balancer health and backend reachability; some resolved Aviator addresses behaved differently";
    // Conservative client-side thresholds for flagging unexpectedly slow connectivity steps.
    private static final long DNS_LATENCY_WARNING_MS = 5000;
    private static final long TCP_LATENCY_WARNING_MS = 2000;
    private static final long TLS_LATENCY_WARNING_MS = 3000;
    private static final long GRPC_LATENCY_WARNING_MS = 10000;

    private AviatorGrpcConnectivityDiagnosticHelper() {}

    public record DiagnosticResult(ArrayNode steps, boolean connectivityFailure) {}

    public static ArrayNode diagnose(String aviatorUrl, String token, long timeoutSeconds, boolean skipAuth) {
        return runDiagnostic(aviatorUrl, token, timeoutSeconds, skipAuth, null).steps();
    }

    public static DiagnosticResult runDiagnostic(String aviatorUrl, String token, long timeoutSeconds, boolean skipAuth,
            Consumer<String> progressConsumer) {
        ArrayNode result = JsonHelper.getObjectMapper().createArrayNode();
        Duration timeout = Duration.ofSeconds(Math.max(1, timeoutSeconds));
        AviatorGrpcClientHelper.AviatorGrpcTarget target = AviatorGrpcClientHelper.parseTarget(aviatorUrl);
        boolean tokenProvided = StringUtils.isNotBlank(token);

        log.debug("Starting Aviator connectivity diagnostic for host={} port={} timeoutSeconds={} skipAuth={} tokenProvided={}",
            target.host(), target.port(), timeoutSeconds, skipAuth, tokenProvided);

        ObjectNode targetStep = createTargetStep(target);
        result.add(targetStep);
        logStepOutcome(targetStep);

        ObjectNode environmentStep = createEnvironmentStep(target);
        result.add(environmentStep);
        logStepOutcome(environmentStep);
        String jvmProxySummary = environmentStep.path("jvmProxySummary").asText("direct");
        boolean directJvmPath = isDirectJvmProxySummary(jvmProxySummary);
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
        String addressProbeProgressMessage = getAddressProbeProgressMessage(directJvmPath, dnsOutcome);
        Object addressProbeProgressArg = directJvmPath ? resolvedAddresses.size() : jvmProxySummary;

        StepOutcome addressProbeOutcome = addStep(result, progressConsumer,
                () -> probeResolvedAddressesOrSkip(target, resolvedAddresses, timeout, directJvmPath,
                        dnsOutcome.allowsDependentSteps(), proxySkipSummary),
                addressProbeProgressMessage,
                addressProbeProgressArg);
        boolean directAddressProbeSucceeded = directJvmPath && addressProbeOutcome.allowsDependentSteps();
        String primaryResolvedAddress = directAddressProbeSucceeded
                ? getPrimaryResolvedAddress(target, resolvedAddresses, addressProbeOutcome.node())
                : null;
        String grpcProbePath = StringUtils.defaultIfBlank(primaryResolvedAddress, target.host());
        String directProbePath = StringUtils.defaultIfBlank(primaryResolvedAddress, target.host());
        String tcpProgressMessage = getTcpProgressMessage(directJvmPath, dnsOutcome.allowsDependentSteps(), directAddressProbeSucceeded);

        StepOutcome tcpOutcome = addStep(result, progressConsumer,
                () -> probeTcpOrSkip(target, primaryResolvedAddress, timeout, directJvmPath,
                        dnsOutcome.allowsDependentSteps(), directAddressProbeSucceeded, proxySkipSummary),
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

        StepOutcome grpcOutcome = addStep(result, progressConsumer,
            () -> grpcTransportProbeAllowed
                ? probeGrpcChannel(target, primaryResolvedAddress, timeout)
                : skippedStep(target, "grpc-channel", "SKIPPED", "Skipped because TLS or ALPN probe failed"),
            grpcTransportProbeAllowed
                ? "Waiting for gRPC channel readiness via %s"
                : "Skipping gRPC channel check because TLS or ALPN failed",
            grpcProbePath);

        addStep(result, progressConsumer,
            () -> !tokenProvided
                ? grpcTransportProbeAllowed
                    ? probeGrpcProbe(target, primaryResolvedAddress, timeout)
                    : skippedStep(target, "grpc-probe", "SKIPPED", "Skipped because TLS or ALPN probe failed")
                : skippedStep(target, "grpc-probe", "SKIPPED", "Skipped because a real token was provided"),
            !tokenProvided
                ? grpcTransportProbeAllowed
                    ? "Probing the gRPC service with an empty token via %s"
                    : "Skipping empty-token gRPC probe because TLS or ALPN failed"
                : "Skipping empty-token gRPC probe because a token was provided",
            grpcProbePath);

        StepOutcome tokenParseOutcome = addStep(result, progressConsumer,
            () -> !tokenProvided
                ? skippedStep(target, "token-parse", "SKIPPED", "Skipped because no token was provided")
                : probeTokenParse(target, token),
            !tokenProvided
                ? "Skipping token parsing because no token was provided"
                : "Parsing the supplied token payload");

        StepOutcome authOutcome;
        if (skipAuth) {
            authOutcome = skippedStep(target, "validate-user-token", "SKIPPED", "Skipped because --skip-auth was specified");
        } else if (!tokenProvided) {
            authOutcome = skippedStep(target, "validate-user-token", "SKIPPED", "Skipped because no token was provided");
        } else if (!grpcOutcome.allowsDependentSteps()) {
            authOutcome = skippedStep(target, "validate-user-token", "SKIPPED", "Skipped because gRPC channel probe did not reach READY state");
        } else if (!tokenParseOutcome.allowsDependentSteps()) {
            authOutcome = skippedStep(target, "validate-user-token", "SKIPPED", "Skipped because token payload could not be parsed");
        } else {
            authOutcome = probeValidateUserToken(target, primaryResolvedAddress, token, timeout);
        }
        String authProgressMessage = getAuthProgressMessage(skipAuth, tokenProvided, grpcOutcome, tokenParseOutcome);
        addStep(result, progressConsumer, () -> authOutcome,
            authProgressMessage,
            grpcProbePath);

        boolean connectivityFailure = hasConnectivityFailure(result);
        log.debug("Completed Aviator connectivity diagnostic for host={} port={} connectivityFailure={}",
                target.host(), target.port(), connectivityFailure);
        return new DiagnosticResult(result, connectivityFailure);
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
        return skippedStep(target, "dns", "SKIPPED", String.format(Locale.ROOT,
                "Skipped because JVM proxy selection is %s; local DNS would not model proxied gRPC traffic",
                jvmProxySummary));
    }

    private static StepOutcome probeResolvedAddressesOrSkip(AviatorGrpcClientHelper.AviatorGrpcTarget target, List<String> resolvedAddresses,
            Duration timeout, boolean directJvmPath, boolean dnsSucceeded, String proxySkipSummary) {
        if ( !directJvmPath ) {
            return skippedStep(target, "address-probes", "SKIPPED", proxySkipSummary);
        }
        if ( !dnsSucceeded ) {
            return skippedStep(target, "address-probes", "SKIPPED", "Skipped because DNS resolution failed");
        }
        return probeResolvedAddresses(target, resolvedAddresses, timeout);
    }

    private static StepOutcome probeTcpOrSkip(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress, Duration timeout,
            boolean directJvmPath, boolean dnsSucceeded, boolean addressProbeSucceeded, String proxySkipSummary) {
        if ( !directJvmPath ) {
            return skippedStep(target, "tcp", "SKIPPED", proxySkipSummary);
        }
        if ( !dnsSucceeded ) {
            return skippedStep(target, "tcp", "SKIPPED", "Skipped because DNS resolution failed");
        }
        if ( !addressProbeSucceeded ) {
            return skippedStep(target, "tcp", "SKIPPED", "Skipped because resolved-address probing found no usable address");
        }
        return probeTcp(target, resolvedAddress, timeout);
    }

    private static StepOutcome probeTlsAndAlpnOrSkip(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress,
            Duration timeout, boolean directJvmPath, StepOutcome tcpOutcome, String proxySkipSummary) {
        if ( !directJvmPath ) {
            return skippedStep(target, "tls-alpn", "SKIPPED", proxySkipSummary);
        }
        if ( !tcpOutcome.allowsDependentSteps() ) {
            return skippedStep(target, "tls-alpn", "SKIPPED", "Skipped because TCP connect failed");
        }
        return probeTlsAndAlpn(target, resolvedAddress, timeout);
    }

    private static String getAddressProbeProgressMessage(boolean directJvmPath, StepOutcome dnsOutcome) {
        if ( !directJvmPath ) {
            return "Skipping resolved-address probes because JVM proxy selection is %s";
        }
        return dnsOutcome.allowsDependentSteps()
                ? "Probing %d resolved address(es) for TCP and TLS consistency"
                : "Skipping resolved-address probes because DNS resolution failed";
    }

    private static String getTcpProgressMessage(boolean directJvmPath, boolean dnsSucceeded, boolean addressProbeSucceeded) {
        if ( !directJvmPath ) {
            return "Skipping TCP connect because JVM proxy selection is %s";
        }
        if ( !dnsSucceeded ) {
            return "Skipping TCP connect because DNS resolution failed";
        }
        return addressProbeSucceeded
                ? "Connecting to %s:%d via %s"
                : "Skipping TCP connect because resolved-address probing found no usable address";
    }

    private static String getTlsProgressMessage(boolean directJvmPath, StepOutcome tcpOutcome) {
        if ( !directJvmPath ) {
            return "Skipping TLS and ALPN because JVM proxy selection is %s";
        }
        return tcpOutcome.allowsDependentSteps()
                ? "Negotiating TLS and ALPN with %s:%d via %s"
                : "Skipping TLS and ALPN because TCP connect failed";
    }

    private static String getAuthProgressMessage(boolean skipAuth, boolean tokenProvided, StepOutcome grpcOutcome,
            StepOutcome tokenParseOutcome) {
        if ( skipAuth ) {
            return "Skipping user-token validation because --skip-auth was specified";
        }
        if ( !tokenProvided ) {
            return "Skipping user-token validation because no token was provided";
        }
        if ( !grpcOutcome.allowsDependentSteps() ) {
            return "Skipping user-token validation because gRPC channel readiness failed";
        }
        return tokenParseOutcome.allowsDependentSteps()
            ? "Validating the supplied user token over gRPC via %s"
                : "Skipping user-token validation because token parsing failed";
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
        if ( step == null || !"FAILED".equals(step.path("status").asText()) ) {
            return false;
        }
        String failureCategory = step.path("failureCategory").asText();
        return isConnectivityStep(step.path("step").asText())
            || "grpc_method_unimplemented".equals(failureCategory)
            || "resolved_addresses_unreachable".equals(failureCategory);
    }

    public static boolean isConnectivityStep(String stepName) {
        return switch ( stepName ) {
            case "dns", "tcp", "tls-alpn", "grpc-channel", "grpc-probe" -> true;
            default -> false;
        };
    }

    private static ObjectNode createTargetStep(AviatorGrpcClientHelper.AviatorGrpcTarget target) {
        ObjectNode step = baseStep(target, "target");
        step.put("status", "OK");
        step.put("durationMs", 0);
        step.put("summary", String.format(Locale.ROOT, "Using %s:%d", target.host(), target.port()));
        step.put("explicitPort", target.explicitPort());
        return step;
    }

    private static StepOutcome probeDns(AviatorGrpcClientHelper.AviatorGrpcTarget target, Duration timeout) {
        Instant start = Instant.now();
        try {
            List<String> addresses = runWithTimeout(timeout, () -> resolveDistinctAddresses(target.host()));
            ObjectNode step = okStep(target, "dns", start,
                    String.format(Locale.ROOT, "Resolved %d address(es)", addresses.size()));
            ArrayNode values = step.putArray("addresses");
            addresses.forEach(values::add);
            step.put("details", String.join(", ", addresses));
            return StepOutcome.success(step);
        } catch (TimeoutException e) {
            ObjectNode step = failedStep(target, "dns", start,
                    String.format(Locale.ROOT, "Timed out resolving %s", target.host()),
                    new FailureInfo("dns_timeout", ACTION_VERIFY_DNS));
            step.put("details", String.format(Locale.ROOT, "DNS resolution exceeded timeout of %d ms", timeout.toMillis()));
            return StepOutcome.failure(step);
        } catch (Exception e) {
            return StepOutcome.failure(errorStep(target, "dns", start, e,
                    String.format(Locale.ROOT, "Could not resolve %s", target.host()),
                    new FailureInfo("dns_resolution_failed", ACTION_VERIFY_DNS)));
        }
    }

    private static StepOutcome probeResolvedAddresses(AviatorGrpcClientHelper.AviatorGrpcTarget target, List<String> addresses, Duration timeout) {
        Instant start = Instant.now();
        if ( addresses.isEmpty() ) {
            return StepOutcome.failure(failedStep(target, "address-probes", start,
                    "No resolved addresses were available for probing",
                    new FailureInfo("dns_resolution_failed", ACTION_VERIFY_DNS)));
        }

        List<ObjectNode> addressResults = addresses.stream()
                .map(address -> CompletableFuture.supplyAsync(() -> probeResolvedAddress(target, address, timeout)))
                .map(CompletableFuture::join)
                .toList();

        long failedCount = addressResults.stream().filter(n -> "FAILED".equals(n.path("status").asText())).count();
        long warningCount = addressResults.stream().filter(n -> "WARN".equals(n.path("status").asText())).count();
        long successfulCount = addressResults.size() - failedCount;

        ObjectNode step = baseStep(target, "address-probes");
        step.put("durationMs", elapsedMillis(start));
        step.put("addressesProbed", addressResults.size());
        step.put("successfulAddresses", successfulCount);
        step.put("failedAddresses", failedCount);
        ArrayNode addressNodes = step.putArray("addresses");
        addressResults.forEach(addressNodes::add);

        if ( failedCount == 0 && warningCount == 0 ) {
            step.put("status", "OK");
            step.put("summary", String.format(Locale.ROOT,
                    "All %d resolved address(es) completed TCP and TLS probing", addressResults.size()));
            applyLatencyInfo(step);
            return StepOutcome.success(step);
        }
        if ( failedCount == 0 ) {
            step.put("status", "WARN");
            step.put("summary", String.format(Locale.ROOT,
                    "All %d resolved address(es) were reachable, but at least one responded slowly", addressResults.size()));
            step.put("recommendedAction", ACTION_CHECK_BACKEND_HEALTH);
            return StepOutcome.success(step);
        }
        if ( successfulCount > 0 ) {
            step.put("status", "WARN");
            step.put("summary", String.format(Locale.ROOT,
                    "%d of %d resolved address(es) completed TCP and TLS probing; backend behavior is inconsistent",
                    successfulCount, addressResults.size()));
            step.put("failureCategory", "partial_backend_failure");
            step.put("recommendedAction", ACTION_CHECK_BACKEND_HEALTH);
            step.put("hint", ACTION_CHECK_BACKEND_HEALTH);
            return StepOutcome.success(step);
        }

        step.put("status", "FAILED");
        step.put("summary", String.format(Locale.ROOT,
                "None of the %d resolved address(es) completed TCP and TLS probing", addressResults.size()));
        addFailureInfo(step, new FailureInfo("resolved_addresses_unreachable", ACTION_CHECK_BACKEND_HEALTH));
        return StepOutcome.failure(step);
    }

    private static ObjectNode probeResolvedAddress(AviatorGrpcClientHelper.AviatorGrpcTarget target, String address, Duration timeout) {
        ObjectNode result = JsonHelper.getObjectMapper().createObjectNode();
        result.put("ip", address);

        Instant tcpStart = Instant.now();
        Instant tlsStart = null;
        try (Socket plainSocket = new Socket()) {
            plainSocket.connect(new InetSocketAddress(address, target.port()), Math.toIntExact(timeout.toMillis()));
            plainSocket.setSoTimeout(Math.toIntExact(timeout.toMillis()));
            result.put("tcpStatus", "OK");
            result.put("tcpDurationMs", elapsedMillis(tcpStart));

            tlsStart = Instant.now();
            try (SSLSocket socket = (SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault())
                    .createSocket(plainSocket, target.host(), target.port(), true)) {
                socket.setSoTimeout(Math.toIntExact(timeout.toMillis()));
                socket.setSSLParameters(createTlsProbeSslParameters(socket.getSSLParameters()));
                socket.startHandshake();
                SSLSession session = socket.getSession();
                String negotiatedProtocol = socket.getApplicationProtocol();
                result.put("tlsDurationMs", elapsedMillis(tlsStart));
                result.put("tlsProtocol", session.getProtocol());
                result.put("cipherSuite", session.getCipherSuite());
                result.put("negotiatedProtocol", StringUtils.defaultIfBlank(negotiatedProtocol, "<none>"));
                addCertificateDetails(result, session.getPeerCertificates());
                if ( !"h2".equals(negotiatedProtocol) ) {
                    FailureInfo failureInfo = new FailureInfo("tls_alpn_missing", ACTION_VERIFY_GRPC_ROUTE);
                    result.put("status", "FAILED");
                    result.put("summary", String.format(Locale.ROOT,
                            "TLS succeeded for %s, but ALPN negotiated %s", address, StringUtils.defaultIfBlank(negotiatedProtocol, "<none>")));
                    result.put("failureCategory", failureInfo.category());
                    result.put("recommendedAction", failureInfo.recommendedAction());
                    return result;
                }
                result.put("tlsStatus", "OK");
                result.put("summary", String.format(Locale.ROOT, "TCP and TLS succeeded for %s", address));
                result.put("status", isSlow(result.path("tcpDurationMs").asLong(), "tcp") || isSlow(result.path("tlsDurationMs").asLong(), "tls-alpn")
                        ? "WARN" : "OK");
                if ( "WARN".equals(result.path("status").asText()) ) {
                    result.put("latencyWarning", true);
                    result.put("summary", String.format(Locale.ROOT, "TCP and TLS succeeded for %s, but the probe was slower than expected", address));
                }
                return result;
            }
        } catch (Exception e) {
            boolean tcpSucceeded = "OK".equals(result.path("tcpStatus").asText());
            FailureInfo failureInfo = tcpSucceeded ? tlsFailureInfo(e) : tcpFailureInfo(e);
            result.put("status", "FAILED");
            if ( tcpSucceeded ) {
                result.put("summary", String.format(Locale.ROOT, "TLS handshake failed for %s:%d", address, target.port()));
                result.put("tlsStatus", "FAILED");
                result.put("tlsDurationMs", tlsStart == null ? 0 : elapsedMillis(tlsStart));
            } else {
                result.put("summary", String.format(Locale.ROOT, "TCP connect failed for %s:%d", address, target.port()));
                result.put("tcpStatus", "FAILED");
                result.put("tcpDurationMs", elapsedMillis(tcpStart));
            }
            result.put("failureCategory", failureInfo.category());
            result.put("recommendedAction", failureInfo.recommendedAction());
            result.put("details", describeException(e));
            return result;
        }
    }

    private static StepOutcome probeTcp(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress, Duration timeout) {
        Instant start = Instant.now();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(resolvedAddress, target.port()), Math.toIntExact(timeout.toMillis()));
            ObjectNode step = okStep(target, "tcp", start,
                    String.format(Locale.ROOT, "Connected to %s:%d via %s", target.host(), target.port(), resolvedAddress));
            step.put("resolvedAddress", resolvedAddress);
            step.put("remoteAddress", socket.getRemoteSocketAddress().toString());
            return StepOutcome.success(step);
        } catch (Exception e) {
            return StepOutcome.failure(errorStep(target, "tcp", start, e,
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
                    ObjectNode step = failedStep(target, "tls-alpn", start,
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

                ObjectNode step = okStep(target, "tls-alpn", start, "TLS handshake succeeded and ALPN negotiated h2");
                step.put("resolvedAddress", resolvedAddress);
                step.put("remoteAddress", plainSocket.getRemoteSocketAddress().toString());
                step.put("negotiatedProtocol", negotiatedProtocol);
                step.put("tlsProtocol", session.getProtocol());
                step.put("cipherSuite", session.getCipherSuite());
                addCertificateDetails(step, session);
                return StepOutcome.success(step);
            }
        } catch (Exception e) {
            return StepOutcome.failure(errorStep(target, "tls-alpn", start, e,
                    String.format(Locale.ROOT, "TLS handshake failed for %s:%d via %s", target.host(), target.port(), resolvedAddress),
                    tlsFailureInfo(e)));
        }
    }

    private static StepOutcome probeGrpcChannel(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress, Duration timeout) {
        Instant start = Instant.now();
        ManagedChannel channel = AviatorGrpcClientHelper.createChannel(target.originalUrl(), resolvedAddress);
        try {
            ArrayNode stateTransitions = JsonHelper.getObjectMapper().createArrayNode();
            ConnectivityState state = channel.getState(true);
            Instant deadline = start.plus(timeout);
            boolean sawTransientFailure = false;
            int transientFailureCount = 0;
            int retryCyclesObserved = 0;
            ConnectivityState previousState = null;
            addStateTransition(stateTransitions, start, state);

            while (Instant.now().isBefore(deadline)) {
                if (state == ConnectivityState.READY) {
                    String summary = sawTransientFailure
                            ? "Channel reached READY after recovering from TRANSIENT_FAILURE"
                            : "Channel reached READY state";
                    ObjectNode step = okStep(target, "grpc-channel", start, summary);
                    putResolvedAddress(step, resolvedAddress);
                    step.put("connectivityState", state.name());
                    step.set("stateTransitions", stateTransitions);
                    step.put("transientFailureCount", transientFailureCount);
                    step.put("retryCyclesObserved", retryCyclesObserved);
                    if (sawTransientFailure) {
                        step.put("details", "The channel temporarily entered TRANSIENT_FAILURE but recovered on retry (normal with multiple backends).");
                    }
                    return StepOutcome.success(step);
                }
                if (state == ConnectivityState.SHUTDOWN) {
                    ObjectNode step = failedStep(target, "grpc-channel", start,
                            "Channel entered SHUTDOWN before READY", grpcChannelFailureInfo(state));
                    putResolvedAddress(step, resolvedAddress);
                    step.put("connectivityState", state.name());
                    step.put("details", describeConnectivityState(state));
                    step.set("stateTransitions", stateTransitions);
                    step.put("transientFailureCount", transientFailureCount);
                    step.put("retryCyclesObserved", retryCyclesObserved);
                    return StepOutcome.failure(step);
                }
                if (state == ConnectivityState.TRANSIENT_FAILURE) {
                    sawTransientFailure = true;
                    if ( previousState != ConnectivityState.TRANSIENT_FAILURE ) {
                        transientFailureCount++;
                    }
                }

                CountDownLatch latch = new CountDownLatch(1);
                channel.notifyWhenStateChanged(state, latch::countDown);
                long remainingMillis = Duration.between(Instant.now(), deadline).toMillis();
                if (remainingMillis <= 0 || !latch.await(remainingMillis, TimeUnit.MILLISECONDS)) {
                    break;
                }
                previousState = state;
                state = channel.getState(false);
                if ( previousState == ConnectivityState.TRANSIENT_FAILURE && state == ConnectivityState.CONNECTING ) {
                    retryCyclesObserved++;
                }
                addStateTransition(stateTransitions, start, state);
            }

            ObjectNode step = failedStep(target, "grpc-channel", start,
                    String.format(Locale.ROOT, "Timed out waiting for READY; last state was %s", state.name()),
                    grpcChannelFailureInfo(state));
            putResolvedAddress(step, resolvedAddress);
            step.put("connectivityState", state.name());
            step.put("details", describeConnectivityState(state));
            step.set("stateTransitions", stateTransitions);
            step.put("transientFailureCount", transientFailureCount);
            step.put("retryCyclesObserved", retryCyclesObserved);
            return StepOutcome.failure(step);
        } catch (Exception e) {
            ObjectNode step = errorStep(target, "grpc-channel", start, e,
                    "gRPC channel could not be established",
                    grpcTransportFailureInfo(describeException(e), new FailureInfo("grpc_channel_error", ACTION_VERIFY_GRPC_ROUTE)));
            putResolvedAddress(step, resolvedAddress);
            return StepOutcome.failure(step);
        } finally {
            shutdownChannel(channel);
        }
    }

    private static StepOutcome probeGrpcProbe(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress, Duration timeout) {
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

                ObjectNode step = okStep(target, "grpc-probe", start,
                    response.getValid()
                        ? "Reached gRPC service; probe RPC unexpectedly accepted an empty token"
                        : buildProbeResponseSummary(response));
                putResolvedAddress(step, resolvedAddress);
            step.put("probeType", "ValidateUserToken(empty-token)");
            return StepOutcome.success(step);
        } catch (StatusRuntimeException e) {
            return classifyProbeException(target, resolvedAddress, start, e);
        } catch (Exception e) {
            ObjectNode step = errorStep(target, "grpc-probe", start, e,
                    "Tokenless gRPC probe could not be completed",
                    new FailureInfo("grpc_probe_failed", ACTION_VERIFY_GRPC_ROUTE));
            putResolvedAddress(step, resolvedAddress);
            return StepOutcome.failure(step);
        } finally {
            shutdownChannel(channel);
        }
    }

    private static StepOutcome probeTokenParse(AviatorGrpcClientHelper.AviatorGrpcTarget target, String token) {
        Instant start = Instant.now();
        try {
            JsonNode payload = getJwtPayload(token);
            String tenantName = getTextClaim(payload, "tenantName");
            String email = getEmailClaim(payload);
            ObjectNode step = okStep(target, "token-parse", start, "Parsed token payload");
            if (tenantName != null) {
                step.put("tenantName", tenantName);
            }
            if (email != null) {
                step.put("email", email);
            }
            return StepOutcome.success(step);
        } catch (Exception e) {
            return StepOutcome.failure(errorStep(target, "token-parse", start, e,
                    "Token payload could not be parsed as a JWT",
                    new FailureInfo("token_parse_error", "Provide a JWT-format Aviator token or use --skip-auth")));
        }
    }

        private static StepOutcome probeValidateUserToken(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress, String token,
            Duration timeout) {
        Instant start = Instant.now();
        String tenantName = getTextClaim(getJwtPayload(token), "tenantName");

        ManagedChannel channel = AviatorGrpcClientHelper.createChannel(target.originalUrl(), resolvedAddress);
        try {
            TokenServiceGrpc.TokenServiceBlockingStub stub = TokenServiceGrpc.newBlockingStub(channel)
                    .withWaitForReady()
                    .withDeadlineAfter(timeout.toSeconds(), TimeUnit.SECONDS);
            TokenValidationResponse response = stub.validateUserToken(ValidateUserTokenRequest.newBuilder()
                    .setToken(token)
                    .setTenantName(tenantName == null ? "" : tenantName)
                    .build());

            if (response.getValid()) {
                ObjectNode step = okStep(target, "validate-user-token", start, "User token was accepted by Aviator");
                putResolvedAddress(step, resolvedAddress);
                if (tenantName != null) {
                    step.put("tenantName", tenantName);
                }
                return StepOutcome.success(step);
            }

            String summary = response.getErrorMessage() == null || response.getErrorMessage().isBlank()
                    ? "Aviator rejected the user token"
                    : response.getErrorMessage();
            ObjectNode step = failedStep(target, "validate-user-token", start, summary,
                    tokenValidationFailureInfo(summary));
            putResolvedAddress(step, resolvedAddress);
            if (tenantName != null) {
                step.put("tenantName", tenantName);
            }
            return StepOutcome.failure(step);
        } catch (StatusRuntimeException e) {
            ObjectNode step = errorStep(target, "validate-user-token", start, e,
                    e.getStatus().getCode() == Status.Code.UNIMPLEMENTED
                            ? "Reached a gRPC endpoint, but ValidateUserToken is not implemented there"
                            : "Token validation RPC failed",
                    tokenValidationFailureInfo(e));
            putResolvedAddress(step, resolvedAddress);
            step.put("grpcStatus", e.getStatus().getCode().name());
            if (tenantName != null) {
                step.put("tenantName", tenantName);
            }
            return StepOutcome.failure(step);
        } catch (Exception e) {
            ObjectNode step = errorStep(target, "validate-user-token", start, e,
                    "Token validation could not be completed",
                    new FailureInfo("token_validation_rpc_failed", ACTION_VERIFY_GRPC_ROUTE));
            putResolvedAddress(step, resolvedAddress);
            return StepOutcome.failure(step);
        } finally {
            shutdownChannel(channel);
        }
    }

    private static StepOutcome skippedStep(AviatorGrpcClientHelper.AviatorGrpcTarget target, String stepName, String status, String summary) {
        ObjectNode step = baseStep(target, stepName);
        step.put("status", status);
        step.put("durationMs", 0);
        step.put("summary", summary);
        return StepOutcome.skipped(step);
    }

    private static ObjectNode okStep(AviatorGrpcClientHelper.AviatorGrpcTarget target, String stepName, Instant start, String summary) {
        ObjectNode step = baseStep(target, stepName);
        step.put("status", "OK");
        step.put("durationMs", elapsedMillis(start));
        step.put("summary", summary);
        applyLatencyInfo(step);
        return step;
    }

    private static ObjectNode failedStep(AviatorGrpcClientHelper.AviatorGrpcTarget target, String stepName, Instant start,
            String summary, FailureInfo failureInfo) {
        ObjectNode step = baseStep(target, stepName);
        step.put("status", "FAILED");
        step.put("durationMs", elapsedMillis(start));
        step.put("summary", summary);
        addFailureInfo(step, failureInfo);
        applyLatencyInfo(step);
        return step;
    }

    private static ObjectNode errorStep(AviatorGrpcClientHelper.AviatorGrpcTarget target, String stepName, Instant start,
            Exception exception, String summary, FailureInfo failureInfo) {
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

    private static ObjectNode baseStep(AviatorGrpcClientHelper.AviatorGrpcTarget target, String stepName) {
        ObjectNode step = JsonHelper.getObjectMapper().createObjectNode();
        step.put("step", stepName);
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
            case TRANSIENT_FAILURE -> "The endpoint accepted earlier network steps, but the gRPC transport failed or was closed before becoming ready.";
            case SHUTDOWN -> "The channel shut down before a working gRPC transport was established.";
        };
    }

    private static String buildProbeResponseSummary(TokenValidationResponse response) {
        String errorMessage = response.getErrorMessage();
        if (errorMessage == null || errorMessage.isBlank()) {
            return "Reached gRPC service; probe RPC returned an application response for the empty token";
        }
        return "Reached gRPC service; probe RPC returned: " + errorMessage;
    }

    private static StepOutcome classifyProbeException(AviatorGrpcClientHelper.AviatorGrpcTarget target, String resolvedAddress, Instant start,
            StatusRuntimeException exception) {
        String statusName = exception.getStatus().getCode().name();
        String description = exception.getStatus().getDescription() == null ? "No additional server details" : exception.getStatus().getDescription();
        boolean serviceReached = isGrpcProbeSuccessStatus(exception.getStatus().getCode());

        boolean isCertError = isCertificateError(description);
        FailureInfo failureInfo = serviceReached ? null : grpcProbeFailureInfo(exception, isCertError);

        ObjectNode step = baseStep(target, "grpc-probe");
        step.put("status", serviceReached ? "OK" : "FAILED");
        step.put("durationMs", elapsedMillis(start));
        putResolvedAddress(step, resolvedAddress);
        step.put("grpcStatus", statusName);
        step.put("details", description);
        step.put("probeType", "ValidateUserToken(empty-token)");
        addFailureInfo(step, failureInfo);
        step.put("summary", buildProbeExceptionSummary(exception, statusName, serviceReached, isCertError));
        return serviceReached ? StepOutcome.success(step) : StepOutcome.failure(step);
    }

    private static String buildProbeExceptionSummary(StatusRuntimeException exception, String statusName, boolean serviceReached,
            boolean certificateError) {
        if ( serviceReached ) {
            return String.format(Locale.ROOT, "Reached gRPC service; probe RPC returned %s", statusName);
        }
        if ( exception.getStatus().getCode() == Status.Code.UNIMPLEMENTED ) {
            return "Reached a gRPC endpoint, but ValidateUserToken is not implemented there";
        }
        if ( certificateError ) {
            return String.format(Locale.ROOT, "Tokenless gRPC probe failed with %s (certificate not trusted - configure truststore)", statusName);
        }
        return String.format(Locale.ROOT, "Tokenless gRPC probe failed with %s", statusName);
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

    private static void addStateTransition(ArrayNode stateTransitions, Instant start, ConnectivityState state) {
        String stateName = state.name();
        if ( stateTransitions.size() > 0 && stateName.equals(stateTransitions.get(stateTransitions.size() - 1).path("state").asText()) ) {
            return;
        }
        long elapsedMs = elapsedMillis(start);
        ObjectNode stateTransition = stateTransitions.addObject();
        stateTransition.put("state", stateName);
        stateTransition.put("elapsedMs", elapsedMs);
        log.debug("Aviator diagnose gRPC channel state={} elapsedMs={}", stateName, elapsedMs);
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
            case UNIMPLEMENTED -> new FailureInfo("grpc_method_unimplemented", ACTION_VERIFY_AVIATOR_ENDPOINT);
            default -> new FailureInfo("grpc_" + exception.getStatus().getCode().name().toLowerCase(Locale.ROOT), ACTION_VERIFY_GRPC_ROUTE);
        };
        return grpcTransportFailureInfo(exception.getStatus().getDescription(), defaultInfo);
    }

    static FailureInfo tokenValidationFailureInfo(String summary) {
        String normalizedSummary = lowerCaseOrEmpty(summary);
        if ( normalizedSummary.contains("expired") ) {
            return new FailureInfo("token_expired", ACTION_RETRY_WITH_FRESH_TOKEN);
        }
        if ( normalizedSummary.contains("invalid") || normalizedSummary.contains("malformed") || normalizedSummary.contains("signature") ) {
            return new FailureInfo("token_invalid", ACTION_RETRY_WITH_FRESH_TOKEN);
        }
        return new FailureInfo("token_rejected", ACTION_RETRY_WITH_FRESH_TOKEN);
    }

    static FailureInfo tokenValidationFailureInfo(StatusRuntimeException exception) {
        boolean certificateError = isCertificateError(exception.getStatus().getDescription());
        if ( certificateError ) {
            return new FailureInfo("tls_untrusted_cert", ACTION_CONFIGURE_TRUSTSTORE);
        }
        FailureInfo defaultInfo = switch ( exception.getStatus().getCode() ) {
            case UNAUTHENTICATED, PERMISSION_DENIED -> new FailureInfo("token_invalid", ACTION_RETRY_WITH_FRESH_TOKEN);
            case DEADLINE_EXCEEDED -> new FailureInfo("grpc_deadline_exceeded", ACTION_VERIFY_GRPC_ROUTE);
            case UNAVAILABLE -> new FailureInfo("grpc_unavailable", ACTION_VERIFY_GRPC_ROUTE);
            case UNIMPLEMENTED -> new FailureInfo("grpc_method_unimplemented", ACTION_VERIFY_AVIATOR_ENDPOINT);
            default -> new FailureInfo("token_validation_rpc_failed", ACTION_VERIFY_GRPC_ROUTE);
        };
        return grpcTransportFailureInfo(exception.getStatus().getDescription(), defaultInfo);
    }

    static boolean isGrpcProbeSuccessStatus(Status.Code statusCode) {
        return switch ( statusCode ) {
            case INVALID_ARGUMENT, PERMISSION_DENIED, UNAUTHENTICATED -> true;
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

    private static ObjectNode createEnvironmentStep(AviatorGrpcClientHelper.AviatorGrpcTarget target) {
        Instant start = Instant.now();
        ObjectNode step = okStep(target, "environment", start, "Collected local runtime context");
        TrustStoreConfigDescriptor trustStoreConfig = TrustStoreConfigHelper.getTrustStoreConfig();
        String normalizedTargetUrl = normalizeUrlForProxyMatch(target.originalUrl());
        List<ProxyDescriptor> matchingProxyConfigs = ProxyHelper.getProxiesStream()
            .filter(descriptor -> descriptor.matches(AVIATOR_MODULE, normalizedTargetUrl))
                .toList();
        String jvmProxySummary = resolveJvmProxySummary(normalizedTargetUrl);

        step.put("jvmVersion", System.getProperty("java.version", "unknown"));
        step.put("jvmVendor", System.getProperty("java.vendor", "unknown"));
        step.put("osName", System.getProperty("os.name", "unknown"));
        step.put("osVersion", System.getProperty("os.version", "unknown"));
        step.put("sslSocketFactory", SSLSocketFactory.getDefault().getClass().getName());
        step.put("grpcSslProvider", resolveGrpcSslProvider());

        String effectiveTrustStorePath = System.getProperty("javax.net.ssl.trustStore");
        String effectiveTrustStoreType = System.getProperty("javax.net.ssl.trustStoreType");
        boolean osTrustStoreConfigured = isOsTrustStoreConfigured(trustStoreConfig);
        boolean osTrustStoreSupported = isOsTrustStoreSupported(System.getProperty("os.name", ""));
        String osTrustStoreStatus = resolveOsTrustStoreStatus(trustStoreConfig, System.getProperty("os.name", ""));
        String trustStoreSource = resolveTrustStoreSource(trustStoreConfig);
        boolean disableOsTrustStoreEnv = EnvHelper.asBoolean(EnvHelper.env("FCLI_DISABLE_OS_TRUSTSTORE"));
        step.put("trustStoreSource", trustStoreSource);
        step.put("trustStoreConfigured", StringUtils.isNotBlank(effectiveTrustStorePath));
        step.put("trustStorePath", StringUtils.defaultIfBlank(effectiveTrustStorePath, "<none>"));
        step.put("trustStoreType", StringUtils.defaultIfBlank(effectiveTrustStoreType, "<default>"));
        step.put("useOsTrustStore", isOsTrustStoreEnabled(trustStoreConfig));
        step.put("osTrustStoreConfigured", osTrustStoreConfigured);
        step.put("osTrustStoreSupported", osTrustStoreSupported);
        step.put("osTrustStoreStatus", osTrustStoreStatus);
        step.put("disableOsTrustStoreEnv", disableOsTrustStoreEnv);
        step.put("effectiveTrustStorePath", StringUtils.defaultIfBlank(effectiveTrustStorePath, "<none>"));
        step.put("effectiveTrustStoreType", StringUtils.defaultIfBlank(effectiveTrustStoreType, "<default>"));
        step.put("trustStorePasswordConfigured", StringUtils.isNotBlank(System.getProperty("javax.net.ssl.trustStorePassword")));

        ArrayNode proxyConfigNames = step.putArray("matchingConfiguredHttpProxyNames");
        matchingProxyConfigs.stream().map(ProxyDescriptor::getName).forEach(proxyConfigNames::add);
        step.put("matchingConfiguredHttpProxyCount", matchingProxyConfigs.size());
        step.put("configuredHttpProxyAppliesToGrpc", false);
        step.put("jvmProxySummary", jvmProxySummary);
        step.put("proxySelectorClass", getProxySelectorClassName());

        ObjectNode envVars = step.putObject("environmentVariables");
        envVars.put("FCLI_TRUSTSTORE", StringUtils.defaultIfBlank(EnvHelper.env("FCLI_TRUSTSTORE"), "<none>"));
        envVars.put("FCLI_TRUSTSTORE_TYPE", StringUtils.defaultIfBlank(EnvHelper.env("FCLI_TRUSTSTORE_TYPE"), "<none>"));
        envVars.put("FCLI_TRUSTSTORE_PWD_CONFIGURED", StringUtils.isNotBlank(EnvHelper.env("FCLI_TRUSTSTORE_PWD")));
        envVars.put("FCLI_DISABLE_OS_TRUSTSTORE", StringUtils.defaultIfBlank(EnvHelper.env("FCLI_DISABLE_OS_TRUSTSTORE"), "<none>"));
        envVars.put("java.net.useSystemProxies", StringUtils.defaultIfBlank(System.getProperty("java.net.useSystemProxies"), "<none>"));
        envVars.put("https.proxyHost", StringUtils.defaultIfBlank(System.getProperty("https.proxyHost"), "<none>"));
        envVars.put("https.proxyPort", StringUtils.defaultIfBlank(System.getProperty("https.proxyPort"), "<none>"));
        envVars.put("http.proxyHost", StringUtils.defaultIfBlank(System.getProperty("http.proxyHost"), "<none>"));
        envVars.put("http.proxyPort", StringUtils.defaultIfBlank(System.getProperty("http.proxyPort"), "<none>"));
        envVars.put("http.nonProxyHosts", StringUtils.defaultIfBlank(System.getProperty("http.nonProxyHosts"), "<none>"));
        envVars.put("socksProxyHost", StringUtils.defaultIfBlank(System.getProperty("socksProxyHost"), "<none>"));
        envVars.put("socksProxyPort", StringUtils.defaultIfBlank(System.getProperty("socksProxyPort"), "<none>"));
        envVars.put("HTTP_PROXY", sanitizeProxyValue(EnvHelper.env("HTTP_PROXY")));
        envVars.put("http_proxy", sanitizeProxyValue(EnvHelper.env("http_proxy")));
        envVars.put("HTTPS_PROXY", sanitizeProxyValue(EnvHelper.env("HTTPS_PROXY")));
        envVars.put("https_proxy", sanitizeProxyValue(EnvHelper.env("https_proxy")));
        envVars.put("ALL_PROXY", sanitizeProxyValue(EnvHelper.env("ALL_PROXY")));
        envVars.put("all_proxy", sanitizeProxyValue(EnvHelper.env("all_proxy")));
        envVars.put("NO_PROXY", StringUtils.defaultIfBlank(EnvHelper.env("NO_PROXY"), "<none>"));
        envVars.put("no_proxy", StringUtils.defaultIfBlank(EnvHelper.env("no_proxy"), "<none>"));

        step.put("summary", buildEnvironmentSummary(
                trustStoreSource,
                osTrustStoreStatus,
                matchingProxyConfigs,
                jvmProxySummary));
        return step;
    }

    private static String buildEnvironmentSummary(String trustStoreSource, String osTrustStoreStatus, List<ProxyDescriptor> matchingProxyConfigs,
            String jvmProxySummary) {
        List<String> details = new ArrayList<>();
        details.add("Java " + System.getProperty("java.version", "unknown"));
        details.add("file-truststore=" + trustStoreSource);
        details.add("os-truststore=" + osTrustStoreStatus);
        if ( !matchingProxyConfigs.isEmpty() ) {
            details.add("http-proxy-configs=" + matchingProxyConfigs.size() + " (ignored by gRPC)");
        }
        details.add("jvm-proxy=" + jvmProxySummary);
        return "Runtime context: " + String.join(", ", details);
    }

    static String resolveJvmProxySummary(String targetUrl) {
        try {
            ProxySelector proxySelector = ProxySelector.getDefault();
            if ( proxySelector == null ) {
                return resolveConfiguredJvmProxySummary();
            }
            List<Proxy> proxies = proxySelector.select(URI.create(targetUrl));
            if ( proxies != null ) {
                for ( Proxy proxy : proxies ) {
                    if ( proxy == null || proxy.type() == Proxy.Type.DIRECT ) {
                        continue;
                    }
                    return formatProxySummary(proxy);
                }
            }
            return "direct";
        } catch (Exception e) {
            log.debug("Unable to resolve JVM proxy selection for {}", targetUrl, e);
            return resolveConfiguredJvmProxySummary();
        }
    }

    private static String getProxySelectorClassName() {
        ProxySelector proxySelector = ProxySelector.getDefault();
        return proxySelector == null ? "<none>" : proxySelector.getClass().getName();
    }

    private static String formatProxySummary(Proxy proxy) {
        SocketAddress address = proxy.address();
        if ( address instanceof InetSocketAddress inetSocketAddress ) {
            return proxy.type().name().toLowerCase(Locale.ROOT)
                    + "://"
                    + inetSocketAddress.getHostString()
                    + formatProxyPort(Integer.toString(inetSocketAddress.getPort()));
        }
        return proxy.type().name().toLowerCase(Locale.ROOT);
    }

    private static String resolveConfiguredJvmProxySummary() {
        String httpsProxyHost = System.getProperty("https.proxyHost");
        if ( StringUtils.isNotBlank(httpsProxyHost) ) {
            return httpsProxyHost + formatProxyPort(System.getProperty("https.proxyPort"));
        }
        String httpProxyHost = System.getProperty("http.proxyHost");
        if ( StringUtils.isNotBlank(httpProxyHost) ) {
            return httpProxyHost + formatProxyPort(System.getProperty("http.proxyPort"));
        }
        String socksProxyHost = System.getProperty("socksProxyHost");
        if ( StringUtils.isNotBlank(socksProxyHost) ) {
            return socksProxyHost + formatProxyPort(System.getProperty("socksProxyPort"));
        }
        if ( EnvHelper.asBoolean(System.getProperty("java.net.useSystemProxies")) ) {
            return "system";
        }
        return "none";
    }

    private static boolean isDirectJvmProxySummary(String jvmProxySummary) {
        return "direct".equalsIgnoreCase(jvmProxySummary) || "none".equalsIgnoreCase(jvmProxySummary);
    }

    private static void putResolvedAddress(ObjectNode step, String resolvedAddress) {
        if ( StringUtils.isNotBlank(resolvedAddress) ) {
            step.put("resolvedAddress", resolvedAddress);
        }
    }

    private static String formatProxyPort(String proxyPort) {
        return StringUtils.isBlank(proxyPort) ? "" : ":" + proxyPort;
    }

    static String resolveTrustStoreSource(TrustStoreConfigDescriptor trustStoreConfig) {
        String effectiveTrustStorePath = System.getProperty("javax.net.ssl.trustStore");
        if ( StringUtils.isBlank(effectiveTrustStorePath) ) {
            return "none";
        }
        if ( trustStoreConfig != null && matchesTrustStorePath(effectiveTrustStorePath, trustStoreConfig.getPath()) ) {
            return "config";
        }
        String envTrustStore = EnvHelper.env("FCLI_TRUSTSTORE");
        if ( matchesTrustStorePath(effectiveTrustStorePath, envTrustStore) ) {
            return "env";
        }
        return "jvm";
    }

    private static boolean matchesTrustStorePath(String effectiveTrustStorePath, String configuredTrustStorePath) {
        if ( StringUtils.isBlank(effectiveTrustStorePath) || StringUtils.isBlank(configuredTrustStorePath) ) {
            return false;
        }
        try {
            return Path.of(effectiveTrustStorePath).toAbsolutePath().normalize()
                    .equals(Path.of(configuredTrustStorePath).toAbsolutePath().normalize());
        } catch (Exception e) {
            return effectiveTrustStorePath.equals(configuredTrustStorePath);
        }
    }

    static boolean isOsTrustStoreEnabled(TrustStoreConfigDescriptor trustStoreConfig) {
        return isOsTrustStoreEnabled(trustStoreConfig, System.getProperty("os.name", ""));
    }

    static boolean isOsTrustStoreEnabled(TrustStoreConfigDescriptor trustStoreConfig, String osName) {
        return isOsTrustStoreConfigured(trustStoreConfig) && isOsTrustStoreSupported(osName);
    }

    static boolean isOsTrustStoreConfigured(TrustStoreConfigDescriptor trustStoreConfig) {
        return !EnvHelper.asBoolean(EnvHelper.env("FCLI_DISABLE_OS_TRUSTSTORE"))
                && (trustStoreConfig == null || !Boolean.FALSE.equals(trustStoreConfig.getUseOsTrustStore()));
    }

    static boolean isOsTrustStoreSupported(String osName) {
        String normalizedOsName = lowerCaseOrEmpty(osName);
        return normalizedOsName.contains("win") || normalizedOsName.contains("mac");
    }

    static String resolveOsTrustStoreStatus(TrustStoreConfigDescriptor trustStoreConfig, String osName) {
        if ( !isOsTrustStoreConfigured(trustStoreConfig) ) {
            return "disabled";
        }
        if ( !isOsTrustStoreSupported(osName) ) {
            return "unsupported";
        }
        return "configured-not-verified";
    }

    private static String resolveGrpcSslProvider() {
        try {
            Class<?> openSslClass = Class.forName("io.grpc.netty.shaded.io.netty.handler.ssl.OpenSsl");
            boolean available = (Boolean)openSslClass.getMethod("isAvailable").invoke(null);
            if ( available ) {
                Object version = openSslClass.getMethod("versionString").invoke(null);
                return StringUtils.isBlank((String)version) ? "OpenSSL" : "OpenSSL (" + version + ")";
            }
            Object cause = openSslClass.getMethod("unavailabilityCause").invoke(null);
            if ( cause instanceof Throwable throwable ) {
                return "JDK TLS (OpenSSL unavailable: " + throwable.getClass().getSimpleName() + ")";
            }
        } catch (Exception e) {
            log.debug("Unable to determine gRPC SSL provider", e);
        }
        return "JDK TLS";
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

    private static String sanitizeProxyValue(String value) {
        if ( StringUtils.isBlank(value) ) {
            return "<none>";
        }
        String normalized = value.contains("://") ? value : "http://" + value;
        try {
            URI uri = URI.create(normalized);
            String userInfo = uri.getUserInfo();
            if ( StringUtils.isBlank(userInfo) ) {
                return value;
            }
            String sanitizedAuthority = "<credentials>@" + uri.getHost() + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
            return uri.getScheme() + "://" + sanitizedAuthority;
        } catch (Exception e) {
            return value.replaceFirst("^[^@]+@", "<credentials>@");
        }
    }

    private static String normalizeUrlForProxyMatch(String originalUrl) {
        return originalUrl.contains("://") ? originalUrl : "https://" + originalUrl;
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

    static String getPrimaryResolvedAddress(AviatorGrpcClientHelper.AviatorGrpcTarget target, List<String> resolvedAddresses,
            ObjectNode addressProbeNode) {
        JsonNode addressesNode = addressProbeNode.path("addresses");
        if ( addressesNode.isArray() ) {
            // Preserve DNS order so downstream probes model the first reachable address the client is likely to try.
            for ( JsonNode addressNode : addressesNode ) {
                if ( !"FAILED".equals(addressNode.path("status").asText()) ) {
                    return addressNode.path("ip").asText(target.host());
                }
            }
        }
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
        if ( "OK".equals(step.path("status").asText()) ) {
            step.put("status", "WARN");
        }
    }

    private static boolean isSlow(long durationMs, String stepName) {
        long thresholdMs = getLatencyThreshold(stepName);
        return thresholdMs > 0 && durationMs > thresholdMs;
    }

    private static long getLatencyThreshold(String stepName) {
        return switch ( stepName ) {
            case "dns" -> DNS_LATENCY_WARNING_MS;
            case "tcp" -> TCP_LATENCY_WARNING_MS;
            case "tls-alpn" -> TLS_LATENCY_WARNING_MS;
            case "grpc-channel", "grpc-probe", "validate-user-token" -> GRPC_LATENCY_WARNING_MS;
            default -> -1;
        };
    }

    private static JsonNode getJwtPayload(String token) {
        if (StringUtils.isBlank(token)) {
            throw new AviatorSimpleException("Provided token is null or blank, cannot extract payload.");
        }

        String[] chunks = token.split("\\.");
        if (chunks.length < 2) {
            throw new AviatorSimpleException(String.format(Locale.ROOT,
                    "Invalid token structure: expected at least 2 parts, but found %d.", chunks.length));
        }

        try {
            byte[] decoded = Base64.getUrlDecoder().decode(chunks[1]);
            return JsonHelper.getObjectMapper().readTree(new String(decoded, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException | IOException e) {
            throw new AviatorSimpleException("The token payload is not a valid Base64URL-encoded JSON document.", e);
        }
    }

    private static String getTextClaim(JsonNode payload, String claimName) {
        JsonNode claimNode = payload == null ? null : payload.get(claimName);
        if (claimNode != null && claimNode.isTextual() && !claimNode.asText().isBlank()) {
            return claimNode.asText();
        }
        return null;
    }

    private static String getEmailClaim(JsonNode payload) {
        String email = getTextClaim(payload, "email");
        return email != null ? email : getTextClaim(payload, "sub");
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