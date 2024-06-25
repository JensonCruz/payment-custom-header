package com.apigee.gateway.callout;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

public class SignatureGenerator_1 implements Execution {

    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {

        try {

            // Set signature header
            messageContext.setVariable("foo", "Hello world");

            return ExecutionResult.SUCCESS;

        } catch (Exception e) {
            e.printStackTrace();
            return ExecutionResult.ABORT;
        }
    }
}
