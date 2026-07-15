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
import java.net.SocketAddress;
import java.net.URI;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fortify.cli.aviator._common.exception.AviatorSimpleException;
import com.fortify.cli.aviator.config.IAviatorLogger;
import com.fortify.cli.aviator.util.Constants;
import com.fortify.cli.common.http.proxy.helper.ProxyDescriptor;
import com.fortify.cli.common.http.proxy.helper.ProxyHelper;
import com.fortify.cli.common.http.ssl.trust.FcliTrustManager;

import io.grpc.CompressorRegistry;
import io.grpc.DecompressorRegistry;
import io.grpc.HttpConnectProxiedSocketAddress;
import io.grpc.ManagedChannel;
import io.grpc.ProxiedSocketAddress;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;

public class AviatorGrpcClientHelper {
    private static final Logger LOG = LoggerFactory.getLogger(AviatorGrpcClientHelper.class);
    private static final String AVIATOR_MODULE = "aviator";

    static record AviatorGrpcTarget(String originalUrl, String host, int port, boolean explicitPort, String channelTarget) {}

    public static AviatorGrpcClient createClient(String url, IAviatorLogger logger, long pingIntervalSeconds) throws AviatorSimpleException {
        ManagedChannel channel = createChannel(url);
        return new AviatorGrpcClient(channel, Constants.DEFAULT_TIMEOUT_SECONDS, logger, pingIntervalSeconds);
    }

    public static AviatorGrpcClient createClient(String url) throws AviatorSimpleException {
        return createClient(url, null, Constants.DEFAULT_PING_INTERVAL_SECONDS);
    }

    static ManagedChannel createChannel(String url) {
        return createChannel(url, null);
    }

    @SuppressWarnings("deprecation")
    static ManagedChannel createChannel(String url, String resolvedAddress) {
        AviatorGrpcTarget target = parseTarget(url);
        Optional<ProxyDescriptor> proxyDescriptor = ProxyHelper.getProxyDescriptorOrEnv(AVIATOR_MODULE, target.originalUrl());
        NettyChannelBuilder builder;
        if ( resolvedAddress != null && !resolvedAddress.isBlank() ) {
            LOG.debug("Using NettyChannelBuilder.forAddress with resolved address {}:{} and authority {}",
                resolvedAddress, target.port(), target.host());
            builder = NettyChannelBuilder.forAddress(resolvedAddress, target.port())
                .overrideAuthority(target.host());
        } else if ( target.explicitPort() ) {
            LOG.debug("Port specified, using NettyChannelBuilder.forAddress: {}:{}", target.host(), target.port());
            builder = NettyChannelBuilder.forAddress(target.host(), target.port());
        } else {
            LOG.debug("No port specified, using NettyChannelBuilder.forTarget: {}", target.channelTarget());
            builder = NettyChannelBuilder.forTarget(target.channelTarget());
        }
        return buildChannel(builder, proxyDescriptor);
    }

    static AviatorGrpcTarget parseTarget(String url) {
        if ( url == null || url.trim().isEmpty() ) {
            throw new AviatorSimpleException("Aviator URL cannot be null or empty.");
        }

        String trimmedUrl = url.trim();
        String urlWithScheme = trimmedUrl.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*") ? trimmedUrl : "https://" + trimmedUrl;

        try {
            URI uri = URI.create(urlWithScheme);
            if ( !"https".equalsIgnoreCase(uri.getScheme()) ) {
                throw new AviatorSimpleException("Aviator URL must use the https scheme. Provided URL: " + url);
            }
            String host = uri.getHost();
            if ( host == null || host.isBlank() ) {
                throw new AviatorSimpleException("Aviator URL is invalid: Host cannot be empty. Provided URL: " + url);
            }

            int port = uri.getPort() == -1 ? 443 : uri.getPort();
            if ( port <= 0 || port > 65535 ) {
                throw new AviatorSimpleException("Aviator URL is invalid: Invalid port number '" + port + "'. Provided URL: " + url);
            }

            if ( uri.getPath() != null && !uri.getPath().isBlank() && !"/".equals(uri.getPath()) ) {
                LOG.warn("WARN: URL contained path '{}', using only host/port for gRPC target. Full URL: {}", uri.getPath(), url);
            }

            boolean explicitPort = uri.getPort() != -1;
            return new AviatorGrpcTarget(trimmedUrl, host, port, explicitPort, host);
        } catch (IllegalArgumentException e) {
            throw new AviatorSimpleException("Aviator URL format is invalid. Expected a valid host or host:port value. Provided URL: " + url, e);
        }
    }

    private static ManagedChannel buildChannel(NettyChannelBuilder builder, Optional<ProxyDescriptor> proxyDescriptor) {
        var configuredBuilder = builder
            .sslContext(createSslContext())
            .maxInboundMessageSize(16 * 1024 * 1024)
            .keepAliveTime(30, TimeUnit.SECONDS)
            .keepAliveTimeout(10, TimeUnit.SECONDS)
            .keepAliveWithoutCalls(true)
            .enableRetry()
            .compressorRegistry(CompressorRegistry.getDefaultInstance())
            .decompressorRegistry(DecompressorRegistry.getDefaultInstance());
        proxyDescriptor.ifPresent(d -> configuredBuilder.proxyDetector(targetAddress -> toProxiedSocketAddress(targetAddress, d)));
        return configuredBuilder.build();
    }

    private static SslContext createSslContext() {
        try {
            return GrpcSslContexts.forClient()
                .trustManager(FcliTrustManager.getInstance())
                .build();
        } catch (Exception e) {
            throw new AviatorSimpleException("Unable to initialize Aviator gRPC TLS context", e);
        }
    }

    static ProxiedSocketAddress toProxiedSocketAddress(SocketAddress targetAddress, ProxyDescriptor proxyDescriptor) {
        if ( !(targetAddress instanceof InetSocketAddress inetSocketAddress) ) {
            return null;
        }

        var builder = HttpConnectProxiedSocketAddress.newBuilder()
            .setTargetAddress(inetSocketAddress)
            .setProxyAddress(new InetSocketAddress(proxyDescriptor.getProxyHost(), proxyDescriptor.getProxyPort()));
        if ( proxyDescriptor.getProxyUser() != null ) {
            builder.setUsername(proxyDescriptor.getProxyUser());
        }
        var proxyPassword = proxyDescriptor.getProxyPasswordAsString();
        if ( proxyPassword != null ) {
            builder.setPassword(proxyPassword);
        }
        return builder.build();
    }
}
