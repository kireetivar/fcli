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

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fortify.cli.aviator.grpc.AviatorGrpcDiagnosticReport.DiagnosticStatus;
import com.fortify.cli.common.http.proxy.helper.ProxyDescriptor;
import com.fortify.cli.common.http.proxy.helper.ProxyHelper;
import com.fortify.cli.common.http.ssl.truststore.helper.TrustStoreConfigDescriptor;
import com.fortify.cli.common.http.ssl.truststore.helper.TrustStoreConfigHelper;
import com.fortify.cli.common.json.JsonHelper;
import com.fortify.cli.common.util.EnvHelper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
final class AviatorGrpcDiagnosticEnvironmentHelper {
    private static final String AVIATOR_MODULE = "aviator";

    private AviatorGrpcDiagnosticEnvironmentHelper() {}

    static ObjectNode createEnvironmentStep(AviatorGrpcClientHelper.AviatorGrpcTarget target) {
        Instant start = Instant.now();
        ObjectNode step = environmentStep(target, start);
        TrustStoreConfigDescriptor trustStoreConfig = TrustStoreConfigHelper.getTrustStoreConfig();
        String normalizedTargetUrl = normalizeUrlForProxyMatch(target.originalUrl());
        List<ProxyDescriptor> matchingProxyConfigs = ProxyHelper.getProxiesStream()
            .filter(descriptor -> descriptor.matches(AVIATOR_MODULE, normalizedTargetUrl))
                .toList();
        String jvmProxySummary = resolveJvmProxySummary(normalizedTargetUrl);

        addRuntimeDetails(step);
        addTrustStoreDetails(step, trustStoreConfig);
        addProxyDetails(step, matchingProxyConfigs, jvmProxySummary);
        addEnvironmentVariables(step);
        step.put("summary", buildEnvironmentSummary(
                step.path("trustStoreSource").asText(),
                step.path("osTrustStoreStatus").asText(),
                matchingProxyConfigs,
                jvmProxySummary));
        return step;
    }

    static boolean isDirectJvmProxySummary(String jvmProxySummary) {
        return "direct".equalsIgnoreCase(jvmProxySummary) || "none".equalsIgnoreCase(jvmProxySummary);
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

    static boolean isOsTrustStoreEnabled(TrustStoreConfigDescriptor trustStoreConfig) {
        return isOsTrustStoreEnabled(trustStoreConfig, System.getProperty("os.name", ""));
    }

    static boolean isOsTrustStoreEnabled(TrustStoreConfigDescriptor trustStoreConfig, String osName) {
        return isOsTrustStoreConfigured(trustStoreConfig) && isOsTrustStoreSupported(osName);
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

    private static ObjectNode environmentStep(AviatorGrpcClientHelper.AviatorGrpcTarget target, Instant start) {
        ObjectNode step = JsonHelper.getObjectMapper().createObjectNode();
        step.put("step", "environment");
        step.put("host", target.host());
        step.put("port", target.port());
        step.put("target", String.format(Locale.ROOT, "%s:%d", target.host(), target.port()));
        step.put("status", DiagnosticStatus.OK.name());
        step.put("durationMs", Duration.between(start, Instant.now()).toMillis());
        step.put("summary", "Collected local runtime context");
        return step;
    }

    private static void addRuntimeDetails(ObjectNode step) {
        step.put("jvmVersion", System.getProperty("java.version", "unknown"));
        step.put("jvmVendor", System.getProperty("java.vendor", "unknown"));
        step.put("osName", System.getProperty("os.name", "unknown"));
        step.put("osVersion", System.getProperty("os.version", "unknown"));
        step.put("sslSocketFactory", SSLSocketFactory.getDefault().getClass().getName());
        step.put("grpcSslProvider", resolveGrpcSslProvider());
    }

    private static void addTrustStoreDetails(ObjectNode step, TrustStoreConfigDescriptor trustStoreConfig) {
        String effectiveTrustStorePath = System.getProperty("javax.net.ssl.trustStore");
        String effectiveTrustStoreType = System.getProperty("javax.net.ssl.trustStoreType");
        boolean osTrustStoreConfigured = isOsTrustStoreConfigured(trustStoreConfig);
        boolean osTrustStoreSupported = isOsTrustStoreSupported(System.getProperty("os.name", ""));
        String osTrustStoreStatus = resolveOsTrustStoreStatus(trustStoreConfig, System.getProperty("os.name", ""));
        boolean disableOsTrustStoreEnv = EnvHelper.asBoolean(EnvHelper.env("FCLI_DISABLE_OS_TRUSTSTORE"));
        step.put("trustStoreSource", resolveTrustStoreSource(trustStoreConfig));
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
    }

    private static void addProxyDetails(ObjectNode step, List<ProxyDescriptor> matchingProxyConfigs, String jvmProxySummary) {
        ArrayNode proxyConfigNames = step.putArray("matchingConfiguredHttpProxyNames");
        matchingProxyConfigs.stream().map(ProxyDescriptor::getName).forEach(proxyConfigNames::add);
        step.put("matchingConfiguredHttpProxyCount", matchingProxyConfigs.size());
        step.put("configuredHttpProxyAppliesToGrpc", false);
        step.put("jvmProxySummary", jvmProxySummary);
        step.put("proxySelectorClass", getProxySelectorClassName());
    }

    private static void addEnvironmentVariables(ObjectNode step) {
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

    private static String formatProxyPort(String proxyPort) {
        return StringUtils.isBlank(proxyPort) ? "" : ":" + proxyPort;
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

    private static boolean isOsTrustStoreConfigured(TrustStoreConfigDescriptor trustStoreConfig) {
        return !EnvHelper.asBoolean(EnvHelper.env("FCLI_DISABLE_OS_TRUSTSTORE"))
                && (trustStoreConfig == null || !Boolean.FALSE.equals(trustStoreConfig.getUseOsTrustStore()));
    }

    private static boolean isOsTrustStoreSupported(String osName) {
        String normalizedOsName = osName == null ? "" : osName.toLowerCase(Locale.ROOT);
        return normalizedOsName.contains("win") || normalizedOsName.contains("mac");
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
}