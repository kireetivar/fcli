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
package com.fortify.cli.common.http.proxy.helper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

class ProxyHelperTest {
    @Test
    void shouldPreferHttpsProxyForHttpsTargets() {
        var env = Map.of(
            "http_proxy", "http://http-proxy.local:8080",
            "https_proxy", "https://https-proxy.local:8443"
        );

        Optional<String> selected = ProxyHelper.getProxyEnvVarName("https", env);

        assertEquals(Optional.of("https_proxy"), selected);
    }

    @Test
    void shouldPreferHttpProxyForHttpTargets() {
        var env = Map.of(
            "http_proxy", "http://http-proxy.local:8080",
            "https_proxy", "https://https-proxy.local:8443"
        );

        Optional<String> selected = ProxyHelper.getProxyEnvVarName("http", env);

        assertEquals(Optional.of("http_proxy"), selected);
    }

    @Test
    void shouldParseProxyFromEnvForSchemeLessTarget() {
        var env = Map.of("https_proxy", "https://user:pwd@proxy.example.com:8443");

        var proxyDescriptor = ProxyHelper.getProxyDescriptorFromEnvVars("aviator.example.com:443", env);

        assertTrue(proxyDescriptor.isPresent());
        assertEquals("proxy.example.com", proxyDescriptor.get().getProxyHost());
        assertEquals(8443, proxyDescriptor.get().getProxyPort());
        assertEquals("user", proxyDescriptor.get().getProxyUser());
        assertEquals("pwd", proxyDescriptor.get().getProxyPasswordAsString());
    }

    @Test
    void shouldRespectNoProxyEnv() {
        var env = Map.of(
            "https_proxy", "https://proxy.example.com:8443",
            "NO_PROXY", "aviator.example.com"
        );

        var proxyDescriptor = ProxyHelper.getProxyDescriptorFromEnvVars("aviator.example.com:443", env);

        assertFalse(proxyDescriptor.isPresent());
    }

    @Test
    void proxyDescriptorShouldMatchSchemeLessUrls() {
        var descriptor = ProxyDescriptor.builder()
            .targetHostNames(Set.of("aviator.example.com"))
            .targetHostNamesMatchMode(ProxyDescriptor.ProxyMatchMode.include)
            .build();

        assertTrue(descriptor.matches("aviator", "aviator.example.com:443"));
    }

    @Test
    void matchesNoProxyRequiresDomainBoundary() {
        assertTrue(ProxyHelper.matchesNoProxy("example.com", "example.com"));
        assertTrue(ProxyHelper.matchesNoProxy("api.example.com", "example.com"));
        assertTrue(ProxyHelper.matchesNoProxy("api.example.com", ".example.com"));
        assertTrue(ProxyHelper.matchesNoProxy("api.example.com", "*.example.com"));
        assertFalse(ProxyHelper.matchesNoProxy("notexample.com", "example.com"));
    }

    @Test
    void matchesNoProxyHandlesCommaSeparatedValuesWithWhitespace() {
        assertTrue(ProxyHelper.matchesNoProxy("api.example.com", "localhost, example.com"));
        assertFalse(ProxyHelper.matchesNoProxy("api.other.com", "localhost, example.com"));
    }

    @Test
    void shouldPreferLowerCaseNoProxyEntryWhenBothCasesArePresent() {
        var env = Map.of(
            "no_proxy", "internal.example.com",
            "NO_PROXY", "example.com",
            "https_proxy", "https://proxy.example.com:8443"
        );

        assertTrue(ProxyHelper.getProxyDescriptorFromEnvVars("internal.example.com:443", env).isEmpty());
        assertFalse(ProxyHelper.getProxyDescriptorFromEnvVars("api.example.com:443", env).isEmpty());
    }
}
