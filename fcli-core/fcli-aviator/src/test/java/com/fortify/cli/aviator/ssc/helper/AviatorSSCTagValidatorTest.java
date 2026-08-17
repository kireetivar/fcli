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
package com.fortify.cli.aviator.ssc.helper;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fortify.cli.aviator.config.IAviatorLogger;
import com.fortify.cli.aviator.util.Constants;
import com.fortify.cli.common.json.JsonHelper;
import com.fortify.cli.common.rest.unirest.UnirestHelper;
import com.fortify.cli.common.rest.unirest.config.UnirestJsonHeaderConfigurer;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import kong.unirest.UnirestInstance;

class AviatorSSCTagValidatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void warnsWhenAviatorStatusValueIsMissing() throws Exception {
        try (TestSscServer server = new TestSscServer(true);
                UnirestInstance unirest = newUnirest(server)) {
            List<String> warnings = AviatorSSCTagValidator.validatePreUpload(
                unirest, "42", null, Set.of(), noOpLogger());

            assertTrue(warnings.stream()
                .anyMatch(warning -> warning.contains(Constants.PROCESSED_BY_AVIATOR_WITH_REMEDIATION)));
        }
    }

    @Test
    void skipsValueValidationWhenSscDoesNotExposeAValueList() throws Exception {
        try (TestSscServer server = new TestSscServer(false);
                UnirestInstance unirest = newUnirest(server)) {
            List<String> warnings = AviatorSSCTagValidator.validatePreUpload(
                unirest, "42", null, Set.of(), noOpLogger());

            assertTrue(warnings.isEmpty());
        }
    }

    private UnirestInstance newUnirest(TestSscServer server) {
        return UnirestHelper.createUnirestInstance(unirest -> {
            UnirestJsonHeaderConfigurer.configure(unirest);
            unirest.config().defaultBaseUrl(server.getBaseUrl());
        });
    }

    private IAviatorLogger noOpLogger() {
        return new IAviatorLogger() {
            @Override public void progress(String format, Object... args) {}
            @Override public void info(String format, Object... args) {}
            @Override public void warn(String format, Object... args) {}
            @Override public void error(String format, Object... args) {}
        };
    }

    private static final class TestSscServer implements AutoCloseable {
        private final HttpServer server;
        private final boolean includeStatusValue;

        private TestSscServer(boolean includeStatusValue) throws IOException {
            this.includeStatusValue = includeStatusValue;
            server = HttpServer.create(new InetSocketAddress(0), 0);
            server.createContext("/api/v1/projectVersions/42/customTags", this::handleVersionTags);
            server.createContext("/api/v1/customTags/1001", this::handleStatusTagDetails);
            server.start();
        }

        private String getBaseUrl() {
            return "http://localhost:" + server.getAddress().getPort();
        }

        private void handleVersionTags(HttpExchange exchange) throws IOException {
            ObjectNode body = MAPPER.createObjectNode();
            ArrayNode tags = body.putArray("data");
            tags.add(tagSummary());
            tags.add(predictionTagSummary());
            writeJson(exchange, body);
        }

        private void handleStatusTagDetails(HttpExchange exchange) throws IOException {
            ObjectNode body = MAPPER.createObjectNode();
            ObjectNode tag = body.putObject("data")
                .put("id", "1001")
                .put("guid", Constants.AVIATOR_STATUS_TAG_ID)
                .put("name", "Aviator status")
                .put("valueType", "LIST");
            if (includeStatusValue) {
                tag.putArray("valueList")
                    .addObject()
                    .put("lookupValue", Constants.PROCESSED_BY_AVIATOR);
            }
            writeJson(exchange, body);
        }

        private JsonNode tagSummary() {
            return JsonHelper.getObjectMapper().createObjectNode()
                .put("id", "1001")
                .put("guid", Constants.AVIATOR_STATUS_TAG_ID)
                .put("name", "Aviator status");
        }

        private JsonNode predictionTagSummary() {
            return JsonHelper.getObjectMapper().createObjectNode()
                .put("id", "1002")
                .put("guid", Constants.AVIATOR_PREDICTION_TAG_ID)
                .put("name", "Aviator prediction");
        }

        private void writeJson(HttpExchange exchange, JsonNode body) throws IOException {
            byte[] response = MAPPER.writeValueAsBytes(body);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream outputStream = exchange.getResponseBody()) {
                outputStream.write(response);
            }
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}