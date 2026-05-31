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

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Stream;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fortify.cli.common.exception.FcliSimpleException;
import com.fortify.cli.common.util.EnvHelper;
import com.fortify.cli.common.util.FcliDataHelper;

import kong.unirest.UnirestInstance;

public final class ProxyHelper {
    private static final Logger LOG = LoggerFactory.getLogger(ProxyHelper.class);
    private static final String[] HTTP_PROXY_ENV_NAMES = {"http_proxy", "HTTP_PROXY"};
    private static final String[] HTTPS_PROXY_ENV_NAMES = {"https_proxy", "HTTPS_PROXY"};
    private static final String[] ALL_PROXY_ENV_NAMES = {"all_proxy", "ALL_PROXY"};
    private static final String[] NO_PROXY_ENV_NAMES = {"no_proxy", "NO_PROXY"};
    private ProxyHelper() {}
    
    public static final void configureProxy(UnirestInstance unirest, String module, String targetUrl) {
        getProxiesStream()
            .sorted(Comparator.comparingInt(ProxyDescriptor::getPriority).reversed())
            .filter(d->d.matches(module, targetUrl))
            .findFirst()
            .ifPresentOrElse(d->
                unirest.config().proxy(d.getProxyHost(), d.getProxyPort(), d.getProxyUser(), d.getProxyPasswordAsString())
                , ()->configureProxyFromEnvVars(unirest, targetUrl)
            );
    }
    
    private static final void configureProxyFromEnvVars(UnirestInstance unirest, String targetUrlString) {
        try {
            var targetUrl = new URL(targetUrlString);
            if ( !matchesNoProxyEnv(targetUrl) ) {
                getProxyEnvVarName(targetUrl).ifPresent(envVar -> configureProxyFromEnvVar(unirest, envVar));
            }
        } catch (Exception e) {
            // We don't want to interfere with potential progress messages, so we
            // just log a debug message.
            LOG.debug("WARN: Unable to configure proxy settings from environment variables", e);
        }
    }

    private static final void configureProxyFromEnvVar(UnirestInstance unirest, String envVarName) {
        var proxyString = EnvHelper.env(envVarName);
        try {
            configureProxyFromUrlEnvVar(unirest, envVarName, new URL(proxyString));
        } catch ( MalformedURLException e ) {
            configureProxyFromNonUrlVar(unirest, envVarName, proxyString);
        }
    }
    
    private static void configureProxyFromUrlEnvVar(UnirestInstance unirest, String envVarName, URL proxyUrl) throws MalformedURLException {
        var host = proxyUrl.getHost();
        var port = proxyUrl.getPort();
        if ( port==-1 ) { port = proxyUrl.getDefaultPort(); }
        var userInfo = proxyUrl.getUserInfo();
        var userInfoElts = StringUtils.isBlank(userInfo) ? null : userInfo.split(":", 2);
        var user = userInfoElts==null || userInfoElts.length==0 ? null : userInfoElts[0];
        var pwd = userInfoElts==null || userInfoElts.length<2 ? null : userInfoElts[1];
        unirest.config().proxy(host, port, user, pwd);
    }

    private static void configureProxyFromNonUrlVar(UnirestInstance unirest, String envVarName, String proxyString) {
        var proxyElts = proxyString.split(":");
        if ( proxyElts.length>2 ) {
            throw new FcliSimpleException(String.format("Unexpected format for environment variable %s: %s", envVarName, proxyString));
        }
        var host = proxyElts[0];
        var port = proxyElts.length<2 ? -1 : Integer.parseInt(proxyElts[1]);
        if ( port==-1 ) {
            var lowerEnvVarName = envVarName.toLowerCase(); 
            if ( lowerEnvVarName.startsWith("http_") ) { port = 80; }
            else if ( lowerEnvVarName.startsWith("https_") ) { port = 443; }
            else { throw new FcliSimpleException(String.format("Unable to determine proxy port from environment variable %s: %s", envVarName, proxyString)); }
        }
        unirest.config().proxy(host, port);
    }

    private static final boolean matchesNoProxyEnv(URL url) {
        return matchesNoProxy(url.getHost(), getNoProxyValue().orElse(null));
    }

    public static final Optional<String> getProxyEnvVarName(String targetUrl) {
        try {
            return getProxyEnvVarName(new URL(targetUrl));
        } catch (MalformedURLException e) {
            return Optional.empty();
        }
    }

    public static final Optional<String> getNoProxyValue() {
        return firstNonBlankEnvValue(NO_PROXY_ENV_NAMES);
    }

    public static final boolean matchesNoProxy(String targetHost, String noProxyValue) {
        if ( StringUtils.isBlank(targetHost) || StringUtils.isBlank(noProxyValue) ) {
            return false;
        }
        String normalizedTargetHost = targetHost.toLowerCase(Locale.ROOT);
        return Arrays.stream(noProxyValue.split(","))
                .map(String::trim)
                .filter(StringUtils::isNotBlank)
                .map(ProxyHelper::normalizeNoProxyEntry)
                .anyMatch(entry -> matchesNoProxyEntry(normalizedTargetHost, entry));
    }

    private static boolean matchesNoProxyEntry(String normalizedTargetHost, String normalizedEntry) {
        return "*".equals(normalizedEntry)
                || (StringUtils.isNotBlank(normalizedEntry)
                        && (normalizedTargetHost.equals(normalizedEntry) || normalizedTargetHost.endsWith("." + normalizedEntry)));
    }

    private static String normalizeNoProxyEntry(String noProxyEntry) {
        String normalizedEntry = noProxyEntry.toLowerCase(Locale.ROOT);
        if ( normalizedEntry.startsWith("*.") ) {
            normalizedEntry = normalizedEntry.substring(2);
        }
        if ( normalizedEntry.startsWith(".") ) {
            normalizedEntry = normalizedEntry.substring(1);
        }
        return normalizedEntry;
    }

    private static Optional<String> firstNonBlankEnvValue(String... envNames) {
        return firstNonBlankEnvName(envNames).map(EnvHelper::env);
    }

    private static Optional<String> firstNonBlankEnvName(String... envNames) {
        return Stream.of(envNames).filter(name -> StringUtils.isNotBlank(EnvHelper.env(name))).findFirst();
    }

    private static Optional<String> getProxyEnvVarName(URL targetUrl) {
        return firstNonBlankEnvName(getProxyEnvNames(targetUrl));
    }

    private static String[] getProxyEnvNames(URL targetUrl) {
        return switch ( StringUtils.defaultString(targetUrl.getProtocol()).toLowerCase(Locale.ROOT) ) {
            case "https" -> concatEnvNames(HTTPS_PROXY_ENV_NAMES, ALL_PROXY_ENV_NAMES);
            case "http" -> concatEnvNames(HTTP_PROXY_ENV_NAMES, ALL_PROXY_ENV_NAMES);
            default -> ALL_PROXY_ENV_NAMES;
        };
    }

    private static String[] concatEnvNames(String[]... envNameGroups) {
        return Stream.of(envNameGroups).flatMap(Arrays::stream).toArray(String[]::new);
    }

    public static final ProxyDescriptor getProxy(String name) {
        Path proxyConfigPath = getProxyConfigPath(name);
        if ( !FcliDataHelper.exists(proxyConfigPath) ) {
            throw new FcliSimpleException("No proxy configuration found with name: "+name);
        }
        return getProxy(proxyConfigPath);
    }
    
    public static final ProxyDescriptor addProxy(ProxyDescriptor descriptor) {
        Path proxyConfigPath = getProxyConfigPath(descriptor);
        if ( FcliDataHelper.exists(proxyConfigPath) ) {
            throw new FcliSimpleException("proxy configuration with name "+descriptor.getName()+" already exists");
        }
        FcliDataHelper.saveSecuredFile(proxyConfigPath, descriptor, true);
        return descriptor;
    }
    
    public static final ProxyDescriptor updateProxy(ProxyDescriptor descriptor) {
        FcliDataHelper.saveSecuredFile(getProxyConfigPath(descriptor), descriptor, true);
        return descriptor;
    }
    
    private static final ProxyDescriptor getProxy(Path proxyDescriptorPath) {
        return FcliDataHelper.readSecuredFile(proxyDescriptorPath, ProxyDescriptor.class, true);
    }
    
    public static final ProxyDescriptor deleteProxy(ProxyDescriptor descriptor) {
        FcliDataHelper.deleteFile(getProxyConfigPath(descriptor), true);
        return descriptor;
    }
    
    public static final Stream<ProxyDescriptor> deleteAllProxies() {
        return getProxiesStream()
                .peek(ProxyHelper::deleteProxy);
    }
    
    public static final Stream<ProxyDescriptor> getProxiesStream() {
        return FcliDataHelper.exists(getProxiesConfigPath())
                ? FcliDataHelper.listFilesInDir(getProxiesConfigPath(), true).map(ProxyHelper::getProxy)
                : Stream.empty();
    }
    
    private static final Path getProxiesConfigPath() {
        return FcliDataHelper.getFcliConfigPath().resolve("proxies");
    }
    
    private static final Path getProxyConfigPath(ProxyDescriptor descriptor) {
        return getProxyConfigPath(descriptor.getName());
    }
    
    private static final Path getProxyConfigPath(String name) {
        return getProxiesConfigPath().resolve(getProxyFileName(name));
    }
    
    private static final String getProxyFileName(String name) {
        return name.replaceAll("[^a-zA-Z0-9]", "_");
    }
}
