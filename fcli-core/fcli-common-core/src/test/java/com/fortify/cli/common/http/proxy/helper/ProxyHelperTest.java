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

import org.junit.jupiter.api.Test;

import com.fortify.cli.common.util.EnvHelper;

class ProxyHelperTest {
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
    void getNoProxyValueHonorsLowercaseOverridePrecedence() {
        String lowerCaseProperty = EnvHelper.envSystemPropertyName("no_proxy");
        String upperCaseProperty = EnvHelper.envSystemPropertyName("NO_PROXY");
        String previousLowerCaseValue = System.getProperty(lowerCaseProperty);
        String previousUpperCaseValue = System.getProperty(upperCaseProperty);
        try {
            System.setProperty(upperCaseProperty, "example.com");
            System.setProperty(lowerCaseProperty, "internal.example.com");

            assertEquals("internal.example.com", ProxyHelper.getNoProxyValue().orElse(null));
        } finally {
            restoreProperty(lowerCaseProperty, previousLowerCaseValue);
            restoreProperty(upperCaseProperty, previousUpperCaseValue);
        }
    }

    @Test
    void getProxyEnvVarNamePrefersHttpsProxyForHttpsTargets() {
        String httpProxyProperty = EnvHelper.envSystemPropertyName("HTTP_PROXY");
        String httpsProxyProperty = EnvHelper.envSystemPropertyName("HTTPS_PROXY");
        String previousHttpProxyValue = System.getProperty(httpProxyProperty);
        String previousHttpsProxyValue = System.getProperty(httpsProxyProperty);
        try {
            System.setProperty(httpProxyProperty, "http://proxy.example.com:8080");
            System.setProperty(httpsProxyProperty, "https://secure-proxy.example.com:8443");

            assertEquals("HTTPS_PROXY", ProxyHelper.getProxyEnvVarName("https://aviator.example.com").orElse(null));
        } finally {
            restoreProperty(httpProxyProperty, previousHttpProxyValue);
            restoreProperty(httpsProxyProperty, previousHttpsProxyValue);
        }
    }

    @Test
    void getProxyEnvVarNamePrefersHttpProxyForHttpTargets() {
        String httpProxyProperty = EnvHelper.envSystemPropertyName("HTTP_PROXY");
        String httpsProxyProperty = EnvHelper.envSystemPropertyName("HTTPS_PROXY");
        String previousHttpProxyValue = System.getProperty(httpProxyProperty);
        String previousHttpsProxyValue = System.getProperty(httpsProxyProperty);
        try {
            System.setProperty(httpProxyProperty, "http://proxy.example.com:8080");
            System.setProperty(httpsProxyProperty, "https://secure-proxy.example.com:8443");

            assertEquals("HTTP_PROXY", ProxyHelper.getProxyEnvVarName("http://ssc.example.com").orElse(null));
        } finally {
            restoreProperty(httpProxyProperty, previousHttpProxyValue);
            restoreProperty(httpsProxyProperty, previousHttpsProxyValue);
        }
    }

    private static void restoreProperty(String propertyName, String value) {
        if ( value == null ) {
            System.clearProperty(propertyName);
        } else {
            System.setProperty(propertyName, value);
        }
    }
}