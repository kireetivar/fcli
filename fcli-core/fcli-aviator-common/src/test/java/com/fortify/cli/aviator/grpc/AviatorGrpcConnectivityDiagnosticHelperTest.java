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

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fortify.cli.common.http.ssl.truststore.helper.TrustStoreConfigDescriptor;
import com.fortify.cli.common.json.JsonHelper;
import com.fortify.cli.common.util.EnvHelper;

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
    void grpcProbeTreatsUnimplementedAsWrongEndpoint() {
        StatusRuntimeException exception = new StatusRuntimeException(Status.UNIMPLEMENTED.withDescription("Method not found"));

        var failureInfo = AviatorGrpcConnectivityDiagnosticHelper.grpcProbeFailureInfo(exception, false);

        assertFalse(AviatorGrpcConnectivityDiagnosticHelper.isGrpcProbeSuccessStatus(Status.Code.UNIMPLEMENTED));
        assertTrue(AviatorGrpcConnectivityDiagnosticHelper.isGrpcProbeSuccessStatus(Status.Code.INVALID_ARGUMENT));
        assertEquals("grpc_method_unimplemented", failureInfo.category());
    }

    @Test
    void tokenValidationClassifiesExpiredTokens() {
        var failureInfo = AviatorGrpcConnectivityDiagnosticHelper.tokenValidationFailureInfo("Token expired at 2026-05-30T00:00:00Z");

        assertEquals("token_expired", failureInfo.category());
    }

    @Test
    void addressProbesAreNotCountedAsPrimaryConnectivitySteps() {
        assertFalse(AviatorGrpcConnectivityDiagnosticHelper.isConnectivityStep("address-probes"));
        assertTrue(AviatorGrpcConnectivityDiagnosticHelper.isConnectivityStep("grpc-channel"));
    }

    @Test
    void wrongEndpointFailuresCountAsConnectivityFailures() {
        ObjectNode wrongEndpointStep = JsonHelper.getObjectMapper().createObjectNode();
        wrongEndpointStep.put("step", "validate-user-token");
        wrongEndpointStep.put("status", "FAILED");
        wrongEndpointStep.put("failureCategory", "grpc_method_unimplemented");

        ObjectNode unreachableAddressesStep = JsonHelper.getObjectMapper().createObjectNode();
        unreachableAddressesStep.put("step", "address-probes");
        unreachableAddressesStep.put("status", "FAILED");
        unreachableAddressesStep.put("failureCategory", "resolved_addresses_unreachable");

        ObjectNode invalidTokenStep = JsonHelper.getObjectMapper().createObjectNode();
        invalidTokenStep.put("step", "validate-user-token");
        invalidTokenStep.put("status", "FAILED");
        invalidTokenStep.put("failureCategory", "token_invalid");

        assertTrue(AviatorGrpcConnectivityDiagnosticHelper.isConnectivityFailureStep(wrongEndpointStep));
        assertTrue(AviatorGrpcConnectivityDiagnosticHelper.isConnectivityFailureStep(unreachableAddressesStep));
        assertFalse(AviatorGrpcConnectivityDiagnosticHelper.isConnectivityFailureStep(invalidTokenStep));
    }

    @Test
    void tlsProbeParametersEnableHostnameVerificationAndHttp2Alpn() {
        SSLParameters sslParameters = AviatorGrpcConnectivityDiagnosticHelper.createTlsProbeSslParameters(new SSLParameters());

        assertEquals("HTTPS", sslParameters.getEndpointIdentificationAlgorithm());
        assertArrayEquals(new String[] {"h2", "http/1.1"}, sslParameters.getApplicationProtocols());
    }

    @Test
    void runWithTimeoutDoesNotPoisonLaterInvocations() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch blocker = new CountDownLatch(1);

        assertThrows(TimeoutException.class,
                () -> AviatorGrpcConnectivityDiagnosticHelper.runWithTimeout(Duration.ofMillis(10), () -> {
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
    void primaryResolvedAddressPrefersFirstNonFailedAddressInDnsOrder() {
        ObjectNode addressProbeNode = JsonHelper.getObjectMapper().createObjectNode();
        ArrayNode addresses = addressProbeNode.putArray("addresses");
        addresses.addObject().put("ip", "10.0.0.1").put("status", "FAILED");
        addresses.addObject().put("ip", "10.0.0.2").put("status", "WARN");
        addresses.addObject().put("ip", "10.0.0.3").put("status", "OK");
        var target = new AviatorGrpcClientHelper.AviatorGrpcTarget(
                "https://aviator.example",
                "aviator.example",
                443,
                false,
                "aviator.example:443");

        String selectedAddress = AviatorGrpcConnectivityDiagnosticHelper.getPrimaryResolvedAddress(
                target,
                List.of("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"),
                addressProbeNode);

        assertEquals("10.0.0.2", selectedAddress);
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

            assertEquals("direct", AviatorGrpcConnectivityDiagnosticHelper.resolveJvmProxySummary("https://direct.example"));
            assertEquals("http://proxy.example:8443",
                    AviatorGrpcConnectivityDiagnosticHelper.resolveJvmProxySummary("https://proxied.example"));
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
            assertEquals("none", AviatorGrpcConnectivityDiagnosticHelper.resolveTrustStoreSource(new TrustStoreConfigDescriptor()));

            System.setProperty("javax.net.ssl.trustStore", tempTrustStore.toString());
            assertEquals("env", AviatorGrpcConnectivityDiagnosticHelper.resolveTrustStoreSource(new TrustStoreConfigDescriptor()));

            System.setProperty("javax.net.ssl.trustStore", otherTrustStore.toString());
            assertEquals("jvm", AviatorGrpcConnectivityDiagnosticHelper.resolveTrustStoreSource(new TrustStoreConfigDescriptor()));
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
                AviatorGrpcConnectivityDiagnosticHelper.resolveOsTrustStoreStatus(new TrustStoreConfigDescriptor(), "Windows 11"));
        assertEquals("configured-not-verified",
                AviatorGrpcConnectivityDiagnosticHelper.resolveOsTrustStoreStatus(new TrustStoreConfigDescriptor(), "Mac OS X"));
        assertEquals("unsupported",
                AviatorGrpcConnectivityDiagnosticHelper.resolveOsTrustStoreStatus(new TrustStoreConfigDescriptor(), "Linux"));
        assertEquals("disabled",
                AviatorGrpcConnectivityDiagnosticHelper.resolveOsTrustStoreStatus(
                        TrustStoreConfigDescriptor.builder().useOsTrustStore(false).build(),
                        "Windows 11"));
    }

    @Test
    void osTrustStoreEnablementHonorsEnvironmentOverrideAndPlatformSupport() {
        String previousDisableOsTrustStore = System.getProperty(EnvHelper.envSystemPropertyName("FCLI_DISABLE_OS_TRUSTSTORE"));
        try {
            assertTrue(AviatorGrpcConnectivityDiagnosticHelper.isOsTrustStoreEnabled(new TrustStoreConfigDescriptor(), "Windows 11"));
            assertTrue(AviatorGrpcConnectivityDiagnosticHelper.isOsTrustStoreEnabled(new TrustStoreConfigDescriptor(), "Mac OS X"));
            assertFalse(AviatorGrpcConnectivityDiagnosticHelper.isOsTrustStoreEnabled(new TrustStoreConfigDescriptor(), "Linux"));
            assertFalse(AviatorGrpcConnectivityDiagnosticHelper.isOsTrustStoreEnabled(
                    TrustStoreConfigDescriptor.builder().useOsTrustStore(false).build(), "Windows 11"));

            System.setProperty(EnvHelper.envSystemPropertyName("FCLI_DISABLE_OS_TRUSTSTORE"), "true");
            assertFalse(AviatorGrpcConnectivityDiagnosticHelper.isOsTrustStoreEnabled(new TrustStoreConfigDescriptor(), "Windows 11"));
        } finally {
            restoreProperty(EnvHelper.envSystemPropertyName("FCLI_DISABLE_OS_TRUSTSTORE"), previousDisableOsTrustStore);
        }
    }

    @Test
    void tokenValidationUnimplementedIndicatesWrongEndpoint() {
        StatusRuntimeException exception = new StatusRuntimeException(Status.UNIMPLEMENTED.withDescription("Method not found"));

        var failureInfo = AviatorGrpcConnectivityDiagnosticHelper.tokenValidationFailureInfo(exception);

        assertEquals("grpc_method_unimplemented", failureInfo.category());
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