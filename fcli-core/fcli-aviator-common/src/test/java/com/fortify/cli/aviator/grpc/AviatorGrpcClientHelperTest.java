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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.fortify.cli.aviator._common.exception.AviatorSimpleException;

class AviatorGrpcClientHelperTest {
    @Test
    void parseTargetUsesDefaultHttpsPortWhenMissing() {
        var target = AviatorGrpcClientHelper.parseTarget("https://eu.aviator.fortify.com/");

        assertEquals("eu.aviator.fortify.com", target.host());
        assertEquals(443, target.port());
        assertFalse(target.explicitPort());
        assertEquals("eu.aviator.fortify.com", target.channelTarget());
    }

    @Test
    void parseTargetPreservesExplicitPort() {
        var target = AviatorGrpcClientHelper.parseTarget("eu.aviator.fortify.com:8443");

        assertEquals("eu.aviator.fortify.com", target.host());
        assertEquals(8443, target.port());
        assertTrue(target.explicitPort());
    }

    @Test
    void parseTargetRejectsMissingHost() {
        assertThrows(AviatorSimpleException.class, () -> AviatorGrpcClientHelper.parseTarget("https:///"));
    }

    @Test
    void parseTargetRejectsNonHttpsScheme() {
        assertThrows(AviatorSimpleException.class, () -> AviatorGrpcClientHelper.parseTarget("http://eu.aviator.fortify.com"));
    }
}