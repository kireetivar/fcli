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
package com.fortify.cli.aviator._common.session.user.cli.cmd;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;

import picocli.CommandLine;
import picocli.CommandLine.ParameterException;

class AviatorUserSessionDiagnoseCommandTest {
    @Test
    void resolveActiveLogFileReturnsNullWhenLoggingIsDisabled() {
        AviatorUserSessionDiagnoseCommand command = parseCommand("--url", "https://aviator.example.com");

        assertNull(command.resolveActiveLogFile());
    }

    @Test
    void resolveActiveLogFileReturnsConfiguredLogFile() {
        AviatorUserSessionDiagnoseCommand command = parseCommand(
                "--url", "https://aviator.example.com", "--log-file", "logs\\diagnose.log");

        assertEquals(Path.of("logs", "diagnose.log").toAbsolutePath(), command.resolveActiveLogFile());
    }

    @Test
    void resolveActiveLogFileReturnsDefaultLogFileForLogLevel() {
        AviatorUserSessionDiagnoseCommand command = parseCommand(
                "--url", "https://aviator.example.com", "--log-level", "INFO");

        assertEquals(Path.of("fcli.log").toAbsolutePath(), command.resolveActiveLogFile());
    }

    @Test
    void resolveActiveLogFileReturnsDefaultLogFileForDebug() {
        AviatorUserSessionDiagnoseCommand command = parseCommand("--url", "https://aviator.example.com", "--debug");

        assertEquals(Path.of("fcli.log").toAbsolutePath(), command.resolveActiveLogFile());
    }

    @Test
    void resolveActiveLogFileReturnsNullForLogLevelNone() {
        AviatorUserSessionDiagnoseCommand command = parseCommand(
                "--url", "https://aviator.example.com", "--log-file", "logs\\diagnose.log", "--log-level", "NONE");

        assertNull(command.resolveActiveLogFile());
    }

    @Test
    void parseAllowsUrlMode() {
        assertDoesNotThrow(() -> new CommandLine(new AviatorUserSessionDiagnoseCommand())
                .parseArgs("--url", "https://aviator.example.com"));
    }

    @Test
    void parseAllowsSessionMode() {
        assertDoesNotThrow(() -> new CommandLine(new AviatorUserSessionDiagnoseCommand())
                .parseArgs("--aviator-session", "team-a"));
    }

    @Test
    void parseAllowsExportOption() {
        assertDoesNotThrow(() -> new CommandLine(new AviatorUserSessionDiagnoseCommand())
                .parseArgs("--url", "https://aviator.example.com", "--export", "diagnose.json"));
    }

    @Test
    void parseRejectsUrlAndSessionTogether() {
        assertThrows(ParameterException.class, () -> new CommandLine(new AviatorUserSessionDiagnoseCommand())
                .parseArgs("--url", "https://aviator.example.com", "--aviator-session", "team-a"));
    }

    private static AviatorUserSessionDiagnoseCommand parseCommand(String... args) {
        AviatorUserSessionDiagnoseCommand command = new AviatorUserSessionDiagnoseCommand();
        new CommandLine(command).parseArgs(args);
        return command;
    }
}