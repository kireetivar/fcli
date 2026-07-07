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
package com.fortify.cli.aviator._main.cli.cmd;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fortify.cli.aviator.grpc.AviatorGrpcDiagnosticReport;
import com.fortify.cli.common.json.JsonHelper;

import picocli.CommandLine;
import picocli.CommandLine.ParameterException;

class AviatorDiagnoseCommandTest {
    @Test
    void parseAllowsUrlMode() {
        assertDoesNotThrow(() -> new CommandLine(new AviatorDiagnoseCommand())
                .parseArgs("--url", "https://aviator.example.com"));
    }

    @Test
    void parseAllowsSessionMode() {
        assertDoesNotThrow(() -> new CommandLine(new AviatorDiagnoseCommand())
                .parseArgs("--aviator-session", "team-a"));
    }

    @Test
    void parseRejectsMissingTarget() {
        assertThrows(ParameterException.class, () -> new CommandLine(new AviatorDiagnoseCommand())
                .parseArgs());
    }

    @Test
    void parseAllowsExportOption() {
        assertDoesNotThrow(() -> new CommandLine(new AviatorDiagnoseCommand())
                .parseArgs("--url", "https://aviator.example.com", "--export", "diagnose.json"));
    }

    @Test
    void parseRejectsUrlAndSessionTogether() {
        assertThrows(ParameterException.class, () -> new CommandLine(new AviatorDiagnoseCommand())
                .parseArgs("--url", "https://aviator.example.com", "--aviator-session", "team-a"));
    }

    @Test
    void verdictKeepsPrimaryAndAdditionalActionsSeparate() {
        ArrayNode steps = JsonHelper.getObjectMapper().createArrayNode();
        ObjectNode step = steps.addObject();
        step.put("step", "grpc-channel");
        step.put("status", "FAILED");
        step.put("failureCategory", "grpc_transient_failure");
        step.put("summary", "TLS succeeded, but the gRPC channel never became READY");
        step.put("recommendedAction", "Check VPN, firewall, proxy, load balancer, or CDN settings for gRPC and HTTP/2 traffic");
        step.putArray("additionalRecommendedActions")
                .add("Verify the configured truststore contains the CA chain required by the Aviator gRPC endpoint");

        var verdict = new AviatorGrpcDiagnosticReport(steps, true).verdict();

        assertEquals("Check VPN, firewall, proxy, load balancer, or CDN settings for gRPC and HTTP/2 traffic",
                verdict.recommendedAction());
        assertEquals(1, verdict.additionalRecommendedActions().size());
        assertTrue(verdict.toDisplayString().contains("next action: Check VPN"));
        assertTrue(verdict.toDisplayString().contains("also check: Verify the configured truststore"));
    }
}