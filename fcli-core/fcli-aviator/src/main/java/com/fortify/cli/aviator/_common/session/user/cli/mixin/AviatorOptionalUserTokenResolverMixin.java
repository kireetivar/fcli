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
package com.fortify.cli.aviator._common.session.user.cli.mixin;

import org.apache.commons.lang3.StringUtils;

import com.fortify.cli.common.cli.mixin.CommonOptionMixins.AbstractTextResolverMixin;
import com.fortify.cli.common.exception.FcliSimpleException;
import com.fortify.cli.common.log.LogSensitivityLevel;
import com.fortify.cli.common.log.MaskValue;

import picocli.CommandLine.Option;

/**
 * Optional resolver for Aviator user tokens from string, file, or environment sources.
 */
public class AviatorOptionalUserTokenResolverMixin extends AbstractTextResolverMixin {
    @Option(names = {"--token", "-t"}, paramLabel = "source", order = 2)
    @MaskValue(sensitivity = LogSensitivityLevel.high, description = "AVIATOR TOKEN")
    private String textSource;

    @Override
    public String getTextSource() {
        return textSource;
    }

    public String getToken() {
        String source = getTextSource();
        if (StringUtils.isBlank(source)) {
            return null;
        }
        if (source.toLowerCase().startsWith("url:")) {
            throw new FcliSimpleException("Providing Aviator tokens via URL ('url:' prefix) is not supported");
        }
        String resolvedToken = super.getText();
        if (StringUtils.isBlank(resolvedToken)) {
            throw new FcliSimpleException("Resolved token value for --token option is blank or empty.");
        }
        return resolvedToken;
    }
}