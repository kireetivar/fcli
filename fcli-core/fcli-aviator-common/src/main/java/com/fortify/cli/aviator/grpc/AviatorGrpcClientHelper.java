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

import java.net.URI;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fortify.cli.aviator._common.exception.AviatorSimpleException;
import com.fortify.cli.aviator.config.IAviatorLogger;
import com.fortify.cli.aviator.util.Constants;

import io.grpc.CompressorRegistry;
import io.grpc.DecompressorRegistry;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class AviatorGrpcClientHelper {
    private static final Logger LOG = LoggerFactory.getLogger(AviatorGrpcClientHelper.class);

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
        if ( resolvedAddress != null && !resolvedAddress.isBlank() ) {
            LOG.debug("Using ManagedChannelBuilder.forAddress with resolved address {}:{} and authority {}",
                    resolvedAddress, target.port(), target.host());
            return buildChannel(ManagedChannelBuilder.forAddress(resolvedAddress, target.port())
                    .overrideAuthority(target.host()));
        }
        if (target.explicitPort()) {
            LOG.debug("Port specified, using ManagedChannelBuilder.forAddress: {}:{}", target.host(), target.port());
            return buildChannel(ManagedChannelBuilder.forAddress(target.host(), target.port()));
        }

        LOG.debug("No port specified, using ManagedChannelBuilder.forTarget: {}", target.channelTarget());
        return buildChannel(ManagedChannelBuilder.forTarget(target.channelTarget()));
    }

    static AviatorGrpcTarget parseTarget(String url) {
        if (url == null || url.trim().isEmpty()) {
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
            if (host == null || host.isBlank()) {
                throw new AviatorSimpleException("Aviator URL is invalid: Host cannot be empty. Provided URL: " + url);
            }

            int port = uri.getPort() == -1 ? 443 : uri.getPort();
            if (port <= 0 || port > 65535) {
                throw new AviatorSimpleException("Aviator URL is invalid: Invalid port number '" + port + "'. Provided URL: " + url);
            }

            if (uri.getPath() != null && !uri.getPath().isBlank() && !"/".equals(uri.getPath())) {
                LOG.warn("WARN: URL contained path '{}', using only host/port for gRPC target. Full URL: {}", uri.getPath(), url);
            }

            boolean explicitPort = uri.getPort() != -1;
            return new AviatorGrpcTarget(trimmedUrl, host, port, explicitPort, host);
        } catch (IllegalArgumentException e) {
            throw new AviatorSimpleException("Aviator URL format is invalid. Expected a valid host or host:port value. Provided URL: " + url, e);
        }
    }

    private static ManagedChannel buildChannel(ManagedChannelBuilder<?> builder) {
        return builder
                .useTransportSecurity()
                .maxInboundMessageSize(16 * 1024 * 1024)
                .keepAliveTime(30, TimeUnit.SECONDS)
                .keepAliveTimeout(10, TimeUnit.SECONDS)
                .keepAliveWithoutCalls(true)
                .enableRetry()
                .compressorRegistry(CompressorRegistry.getDefaultInstance())
                .decompressorRegistry(DecompressorRegistry.getDefaultInstance())
                .build();
    }

}