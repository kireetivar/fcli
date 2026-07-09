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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.SSLParameters;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fortify.cli.common.http.ssl.truststore.helper.TrustStoreConfigDescriptor;
import com.fortify.cli.common.json.JsonHelper;
import com.fortify.cli.common.util.EnvHelper;
import com.fortify.grpc.token.TokenValidationResponse;

import io.grpc.ConnectivityState;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;

class AviatorGrpcConnectivityDiagnosticHelperTest {
    private static final String TEST_CERTIFICATE = """
            -----BEGIN CERTIFICATE-----
            MIIDgDCCAmigAwIBAgIJALMCBJJgH7+0MA0GCSqGSIb3DQEBDAUAMG4xCzAJBgNV
            BAYTAkNBMQswCQYDVQQIEwJCQzESMBAGA1UEBxMJVmFuY291dmVyMREwDwYDVQQK
            EwhPcGVuVGV4dDELMAkGA1UECxMCUUExHjAcBgNVBAMTFWRpYWdub3NlLXRlc3Qu
            ZXhhbXBsZTAeFw0yNjA1MzAxMTI1MzNaFw0yNzA1MzAxMTI1MzNaMG4xCzAJBgNV
            BAYTAkNBMQswCQYDVQQIEwJCQzESMBAGA1UEBxMJVmFuY291dmVyMREwDwYDVQQK
            EwhPcGVuVGV4dDELMAkGA1UECxMCUUExHjAcBgNVBAMTFWRpYWdub3NlLXRlc3Qu
            ZXhhbXBsZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANML244R2gbf
            INIoaU79e4Tt253bDxGkk9v6yXcOL+8A7NgnOnm/pAvZynSzRPut13IgrdTt2h2r
            zq4r2B0KT8pp2LsfeMKDennljlvnRUWOh0hA0wqx6FycPRI55+NOZ780NuIY1aKW
            YvGMarNK0kcnEVVUwaOv5CAJjfkuKSTZULq6cBm1/JRrvhFDZABkHGoWmWj8USmb
            C+1ZWUgpBIJtGpB2HGmTaV+EUijJjth8ifhJY+ArjYYEuCiGtGpm3TPOquMLxwuI
            vMoQBkT3SdIiSQYJwFTAYXh4Qhz/2RefhJEQEj1Ut+6ePPZh8e+gcosu+2c2uNry
            YoLHYdoJgEcCAwEAAaMhMB8wHQYDVR0OBBYEFHShgq2RpDXjIFQ1IM+uk29+bQeP
            MA0GCSqGSIb3DQEBDAUAA4IBAQANY5ZQ5g9BipoCyh3CU307pZcpnZsY+16Sp/4P
            YAH6P4mfM2w6Ry6+JOED0q0P1zkQwCuNppUGQW3vhsP7Fku5jyjjMjQrlu3nrul0
            2j2X1aXVKjd9o3kSPsIVxkO2MzcuA0V4iOj6wkZ+xKWrYOPQiWWBjnFiayTyOFd0
            nTwUh07JER75h2NMXNwbACaQjRFReJ0WL7w3LL4sLSRtcNBBAosISz+OSXmLMMbI
            bcXVARK2NlyWY19rtsWRZQd7WNGMGqYjk/6+eYaiC7mFAdazEaVSV6/Vu2o5VajD
            qQ5CHGLEgTsRHvMk129T+eu+XTvkIQicGH2NEqkZ+Mx0Cnr0
            -----END CERTIFICATE-----
            """;

    @Test
    void grpcProbeClassifiesDeadlineExceeded() {
        StatusRuntimeException exception = new StatusRuntimeException(Status.DEADLINE_EXCEEDED.withDescription("deadline exceeded"));

        var failureInfo = AviatorGrpcConnectivityDiagnosticHelper.grpcProbeFailureInfo(exception, false);

        assertEquals("grpc_deadline_exceeded", failureInfo.category());
    }

    @Test
    void grpcProbeClassifiesGoAwayAsDistinctTransportFailure() {
        StatusRuntimeException exception = new StatusRuntimeException(
                Status.UNAVAILABLE.withDescription("Received GOAWAY with error code ENHANCE_YOUR_CALM"));

        var failureInfo = AviatorGrpcConnectivityDiagnosticHelper.grpcProbeFailureInfo(exception, false);

        assertEquals("grpc_goaway", failureInfo.category());
    }

    @Test
    void grpcProbeClassifiesUnavailable() {
        StatusRuntimeException exception = new StatusRuntimeException(
                Status.UNAVAILABLE.withDescription("upstream connect error or disconnect/reset before headers"));

        var failureInfo = AviatorGrpcConnectivityDiagnosticHelper.grpcProbeFailureInfo(exception, false);

        assertEquals("grpc_unavailable", failureInfo.category());
    }

    @Test
    void grpcProbeClassifiesRstStreamAsDistinctTransportFailure() {
        StatusRuntimeException exception = new StatusRuntimeException(
                Status.UNAVAILABLE.withDescription("Stream closed after receiving RST_STREAM with error code 2"));

        var failureInfo = AviatorGrpcConnectivityDiagnosticHelper.grpcProbeFailureInfo(exception, false);

        assertEquals("grpc_rst_stream", failureInfo.category());
    }

    @Test
    void grpcProbeTreatsUnimplementedAsServiceReached() {
        assertTrue(AviatorGrpcConnectivityDiagnosticHelper.isGrpcProbeSuccessStatus(Status.Code.UNIMPLEMENTED));
        assertTrue(AviatorGrpcConnectivityDiagnosticHelper.isGrpcProbeSuccessStatus(Status.Code.INVALID_ARGUMENT));
    }

    @Test
    void grpcChannelExceptionClassifiesCertificateErrorsAsTruststoreFailures() {
        var failureInfo = AviatorGrpcConnectivityDiagnosticHelper.grpcChannelExceptionFailureInfo(
                "PKIX path building failed: unable to find valid certification path to requested target");

        assertEquals("tls_untrusted_cert", failureInfo.category());
        assertEquals("Run 'fcli config truststore set' to configure a custom truststore", failureInfo.recommendedAction());
    }

    @Test
    void grpcChannelExceptionClassifiesGoAwayAsConcreteTransportReset() {
        var failureInfo = AviatorGrpcConnectivityDiagnosticHelper.grpcChannelExceptionFailureInfo(
                "Received GOAWAY with error code ENHANCE_YOUR_CALM");

        assertEquals("grpc_goaway", failureInfo.category());
        assertEquals("Check the Aviator gRPC path for HTTP/2 GOAWAY or RST_STREAM resets before the channel becomes READY",
                failureInfo.recommendedAction());
    }

    @Test
    void grpcChannelExceptionSummaryMentionsObservedGoAway() {
        String summary = AviatorGrpcConnectivityDiagnosticHelper.buildGrpcChannelExceptionSummary(
                "Received GOAWAY with error code ENHANCE_YOUR_CALM");

        assertEquals("The gRPC channel could not be established because the upstream gRPC path sent GOAWAY before READY", summary);
    }

    @Test
    void grpcResponseSummaryTreatsEmptyTokenRejectionAsReachabilitySuccess() {
        String summary = AviatorGrpcConnectivityDiagnosticHelper.buildGrpcResponseSummary(
                TokenValidationResponse.newBuilder()
                        .setValid(false)
                        .setErrorMessage("Token validation failed.")
                        .build());

        assertEquals(
                "Received a gRPC application response to the connectivity probe; Aviator rejected the expected empty probe token, which confirms end-to-end gRPC reachability",
                summary);
    }

    @Test
    void grpcChannelTransientFailureTimeoutMentionsLoadBalancerPath() {
        String summary = AviatorGrpcConnectivityDiagnosticHelper.buildGrpcChannelTimeoutSummary(ConnectivityState.TRANSIENT_FAILURE);

        assertTrue(summary.contains("VPN, firewall, proxy, load balancer, or backend gRPC listener"));
        assertTrue(summary.contains("TRANSIENT_FAILURE"));
    }

    @Test
    void grpcChannelFailureMentionsConfiguredTrustStoreWhenActive() {
        ObjectNode step = JsonHelper.getObjectMapper().createObjectNode();
        step.put("step", "aviator-server-channel");
        step.put("status", "FAILED");
        step.put("summary", "TLS succeeded, but the gRPC channel never became READY");
        step.put("recommendedAction", "Check VPN, firewall, proxy, load balancer, or CDN settings for gRPC and HTTP/2 traffic");
        ObjectNode environmentStep = JsonHelper.getObjectMapper().createObjectNode();
        environmentStep.put("trustStoreSource", "config");

        AviatorGrpcDiagnosticActionHelper.addTrustStoreContextIfApplicable(step, environmentStep);
        AviatorGrpcDiagnosticActionHelper.addTrustStoreContextIfApplicable(step, environmentStep);

        assertTrue(step.path("summary").asText().contains("configured truststore"));
        assertTrue(step.path("summary").asText().contains("VPN, proxy, firewall, or load balancer"));
        assertEquals("Check VPN, firewall, proxy, load balancer, or CDN settings for gRPC and HTTP/2 traffic",
            step.path("recommendedAction").asText());
        assertEquals("Verify the configured truststore contains the CA chain required by the Aviator gRPC endpoint",
            step.path("additionalRecommendedActions").get(0).asText());
        assertEquals(1, step.path("additionalRecommendedActions").size());
        assertFalse(step.path("recommendedAction").asText().contains("clear"));
    }

    @Test
    void grpcChannelTrustStoreContextIsNotAddedWhenPrimaryRecommendationIsAlreadyTruststore() {
        ObjectNode step = JsonHelper.getObjectMapper().createObjectNode();
        step.put("step", "aviator-server-channel");
        step.put("status", "FAILED");
        step.put("summary", "The gRPC channel could not be established because the server certificate is not trusted");
        step.put("failureCategory", "tls_untrusted_cert");
        step.put("recommendedAction", "Run 'fcli config truststore set' to configure a custom truststore");
        ObjectNode environmentStep = JsonHelper.getObjectMapper().createObjectNode();
        environmentStep.put("trustStoreSource", "config");

        AviatorGrpcDiagnosticActionHelper.addTrustStoreContextIfApplicable(step, environmentStep);

        assertFalse(step.has("additionalRecommendedActions"));
        assertEquals("The gRPC channel could not be established because the server certificate is not trusted",
                step.path("summary").asText());
    }

    @Test
    void connectivityStepsMatchDefaultProbePipeline() {
        assertTrue(AviatorGrpcConnectivityDiagnosticHelper.isConnectivityStep("aviator-server-channel"));
        assertTrue(AviatorGrpcConnectivityDiagnosticHelper.isConnectivityStep("aviator-server-response"));
        assertFalse(AviatorGrpcConnectivityDiagnosticHelper.isConnectivityStep("address-probes"));
    }

    @Test
    void requiredTransportFailuresCountAsConnectivityFailures() {
        ObjectNode grpcResponseFailureStep = JsonHelper.getObjectMapper().createObjectNode();
        grpcResponseFailureStep.put("step", "aviator-server-response");
        grpcResponseFailureStep.put("status", "FAILED");
        grpcResponseFailureStep.put("failureCategory", "grpc_deadline_exceeded");

        ObjectNode grpcResponseWarningStep = JsonHelper.getObjectMapper().createObjectNode();
        grpcResponseWarningStep.put("step", "aviator-server-response");
        grpcResponseWarningStep.put("status", "WARN");
        grpcResponseWarningStep.put("failureCategory", "grpc_method_unimplemented");

        assertTrue(AviatorGrpcConnectivityDiagnosticHelper.isConnectivityFailureStep(grpcResponseFailureStep));
        assertFalse(AviatorGrpcConnectivityDiagnosticHelper.isConnectivityFailureStep(grpcResponseWarningStep));
    }

    @Test
    void tlsProbeParametersEnableHostnameVerificationAndHttp2Alpn() {
        SSLParameters sslParameters = AviatorGrpcConnectivityDiagnosticHelper.createTlsProbeSslParameters(new SSLParameters());

        assertEquals("HTTPS", sslParameters.getEndpointIdentificationAlgorithm());
        assertArrayEquals(new String[] {"h2", "http/1.1"}, sslParameters.getApplicationProtocols());
    }

    @Test
    void runWithTimeoutDoesNotPoisonLaterInvocations() throws Exception {
        Duration firstTimeout = Duration.ofMillis(250);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch blocker = new CountDownLatch(1);

        assertThrows(TimeoutException.class,
                () -> AviatorGrpcConnectivityDiagnosticHelper.runWithTimeout(firstTimeout, () -> {
                    started.countDown();
                    while ( true ) {
                        try {
                            blocker.await();
                        } catch (InterruptedException ignored) {
                            // Simulate a blocking DNS resolver that doesn't stop when interrupted.
                        }
                    }
                }));

        assertTrue(started.await(1, TimeUnit.SECONDS));
        assertEquals("ok", AviatorGrpcConnectivityDiagnosticHelper.runWithTimeout(Duration.ofMillis(100), () -> "ok"));
    }

    @Test
    void primaryResolvedAddressUsesFirstDnsAddress() {
        var target = new AviatorGrpcClientHelper.AviatorGrpcTarget(
                "https://aviator.example",
                "aviator.example",
                443,
                false,
                "aviator.example:443");

        String selectedAddress = AviatorGrpcConnectivityDiagnosticHelper.getPrimaryResolvedAddress(
                target, List.of("10.0.0.1", "10.0.0.2"));

        assertEquals("10.0.0.1", selectedAddress);
    }

    @Test
    void primaryResolvedAddressFallsBackToHostWhenDnsAddressListIsEmpty() {
        var target = new AviatorGrpcClientHelper.AviatorGrpcTarget(
                "https://aviator.example",
                "aviator.example",
                443,
                false,
                "aviator.example:443");

        String selectedAddress = AviatorGrpcConnectivityDiagnosticHelper.getPrimaryResolvedAddress(target, List.of());

        assertEquals("aviator.example", selectedAddress);
    }

    @Test
    void jvmProxySummaryUsesTargetSpecificProxySelectorResult() {
        ProxySelector previousProxySelector = ProxySelector.getDefault();
        try {
            ProxySelector.setDefault(new ProxySelector() {
                @Override
                public List<Proxy> select(URI uri) {
                    if ( "direct.example".equals(uri.getHost()) ) {
                        return List.of(Proxy.NO_PROXY);
                    }
                    return List.of(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("proxy.example", 8443)));
                }

                @Override
                public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {}
            });

                assertEquals("direct", AviatorGrpcDiagnosticEnvironmentHelper.resolveJvmProxySummary("https://direct.example"));
            assertEquals("http://proxy.example:8443",
                    AviatorGrpcDiagnosticEnvironmentHelper.resolveJvmProxySummary("https://proxied.example"));
        } finally {
            ProxySelector.setDefault(previousProxySelector);
        }
    }

    @Test
    void resolveTrustStoreSourceIgnoresEnvPathUntilRuntimeActivatesIt() throws Exception {
        Path tempTrustStore = Files.createTempFile("aviator-diagnose", ".jks");
        Path otherTrustStore = Files.createTempFile("aviator-diagnose-other", ".jks");
        String previousEnvTrustStore = System.getProperty(EnvHelper.envSystemPropertyName("FCLI_TRUSTSTORE"));
        String previousTrustStore = System.getProperty("javax.net.ssl.trustStore");
        try {
            System.setProperty(EnvHelper.envSystemPropertyName("FCLI_TRUSTSTORE"), tempTrustStore.toString());
            System.clearProperty("javax.net.ssl.trustStore");
            assertEquals("none", AviatorGrpcDiagnosticEnvironmentHelper.resolveTrustStoreSource(new TrustStoreConfigDescriptor()));

            System.setProperty("javax.net.ssl.trustStore", tempTrustStore.toString());
            assertEquals("env", AviatorGrpcDiagnosticEnvironmentHelper.resolveTrustStoreSource(new TrustStoreConfigDescriptor()));

            System.setProperty("javax.net.ssl.trustStore", otherTrustStore.toString());
            assertEquals("jvm", AviatorGrpcDiagnosticEnvironmentHelper.resolveTrustStoreSource(new TrustStoreConfigDescriptor()));
        } finally {
            restoreProperty(EnvHelper.envSystemPropertyName("FCLI_TRUSTSTORE"), previousEnvTrustStore);
            restoreProperty("javax.net.ssl.trustStore", previousTrustStore);
            Files.deleteIfExists(tempTrustStore);
            Files.deleteIfExists(otherTrustStore);
        }
    }

    @Test
    void osTrustStoreStatusReflectsSupportedAndUnsupportedPlatforms() {
        assertEquals("configured-not-verified",
                AviatorGrpcDiagnosticEnvironmentHelper.resolveOsTrustStoreStatus(new TrustStoreConfigDescriptor(), "Windows 11"));
        assertEquals("configured-not-verified",
                AviatorGrpcDiagnosticEnvironmentHelper.resolveOsTrustStoreStatus(new TrustStoreConfigDescriptor(), "Mac OS X"));
        assertEquals("unsupported",
                AviatorGrpcDiagnosticEnvironmentHelper.resolveOsTrustStoreStatus(new TrustStoreConfigDescriptor(), "Linux"));
        assertEquals("disabled",
                AviatorGrpcDiagnosticEnvironmentHelper.resolveOsTrustStoreStatus(
                        TrustStoreConfigDescriptor.builder().useOsTrustStore(false).build(),
                        "Windows 11"));
    }

    @Test
    void osTrustStoreEnablementHonorsEnvironmentOverrideAndPlatformSupport() {
        String previousDisableOsTrustStore = System.getProperty(EnvHelper.envSystemPropertyName("FCLI_DISABLE_OS_TRUSTSTORE"));
        try {
                assertTrue(AviatorGrpcDiagnosticEnvironmentHelper.isOsTrustStoreEnabled(new TrustStoreConfigDescriptor(), "Windows 11"));
                assertTrue(AviatorGrpcDiagnosticEnvironmentHelper.isOsTrustStoreEnabled(new TrustStoreConfigDescriptor(), "Mac OS X"));
                assertFalse(AviatorGrpcDiagnosticEnvironmentHelper.isOsTrustStoreEnabled(new TrustStoreConfigDescriptor(), "Linux"));
                assertFalse(AviatorGrpcDiagnosticEnvironmentHelper.isOsTrustStoreEnabled(
                    TrustStoreConfigDescriptor.builder().useOsTrustStore(false).build(), "Windows 11"));

            System.setProperty(EnvHelper.envSystemPropertyName("FCLI_DISABLE_OS_TRUSTSTORE"), "true");
                assertFalse(AviatorGrpcDiagnosticEnvironmentHelper.isOsTrustStoreEnabled(new TrustStoreConfigDescriptor(), "Windows 11"));
        } finally {
            restoreProperty(EnvHelper.envSystemPropertyName("FCLI_DISABLE_OS_TRUSTSTORE"), previousDisableOsTrustStore);
        }
    }

    private static void restoreProperty(String propertyName, String value) {
        if ( value == null ) {
            System.clearProperty(propertyName);
        } else {
            System.setProperty(propertyName, value);
        }
    }

    @Test
    void addCertificateDetailsExtractsLeafMetadata() throws Exception {
        Certificate certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(TEST_CERTIFICATE.getBytes(StandardCharsets.US_ASCII)));
        ObjectNode node = JsonHelper.getObjectMapper().createObjectNode();

        AviatorGrpcConnectivityDiagnosticHelper.addCertificateDetails(node, new Certificate[] {certificate});

        assertEquals(1, node.path("certificateChainLength").asInt());
        assertTrue(node.path("certSubject").asText().contains("CN=diagnose-test.example"));
        assertTrue(node.path("certIssuer").asText().contains("CN=diagnose-test.example"));
        assertTrue(node.path("certExpiry").asText().startsWith("2027-05-30T11:25:33Z"));
        assertTrue(node.path("certSelfSigned").asBoolean());
        assertFalse(node.path("peerCertificates").isEmpty());
    }
}