package com.apigee.gateway.callout;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.format.DateTimeFormatter;
import java.time.ZonedDateTime;
import java.time.ZoneOffset;

public class SignatureGenerator implements Execution {

    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {

        try {
            // Retrieve necessary variables
            String payload = (String) messageContext.getVariable("request.content");
            String sharedKey = (String) messageContext.getVariable("shared.key");
            String merchantKeyId = (String) messageContext.getVariable("merchant.keyid");
            String requestHost = (String) messageContext.getVariable("request.host");
            String merchantId = (String) messageContext.getVariable("merchant.id");
            String resource = (String) messageContext.getVariable("resource");
            String method = (String) messageContext.getVariable("request.verb");

            // Generate v-c-date
            String gmtDate = DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneOffset.UTC));
            messageContext.setVariable("v-c-date", gmtDate);

            // Generate digest
            String digest = generateDigest(payload);
            String digestHeader = "SHA-256=" + digest;
            messageContext.setVariable("digest", digestHeader);

            // Construct the signature string
            StringBuilder signatureString = new StringBuilder();
            signatureString.append("host: ").append(requestHost).append("\n");
            signatureString.append("date: ").append(gmtDate).append("\n");
            signatureString.append("request-target: ").append(method).append(" ").append(resource).append("\n");
            signatureString.append("digest: ").append(digestHeader).append("\n");
            signatureString.append("v-c-merchant-id: ").append(merchantId);

            // Generate HMAC signature using MessageDigest
            String signature = generateHMACSHA256Signature(sharedKey, signatureString.toString());
            String signatureHeader = "keyid=\"" + merchantKeyId + "\", algorithm=\"HmacSHA256\", headers=\"host date request-target digest v-c-merchant-id\", signature=\"" + signature + "\"";

            // Set signature header
            messageContext.setVariable("signature", signatureHeader);

            return ExecutionResult.SUCCESS;

        } catch (Exception e) {
            e.printStackTrace();
            return ExecutionResult.ABORT;
        }
    }

    private String generateDigest(String payload) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    private String generateHMACSHA256Signature(String sharedKey, String validationString)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] keyBytes = Base64.getDecoder().decode(sharedKey);
        SecretKey originalKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "HmacSHA256");
//        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");

        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        hmacSha256.init(originalKey);
        hmacSha256.update(validationString.getBytes());
        byte[] HmachSha256DigestBytes = hmacSha256.doFinal();
        return Base64.getEncoder().encodeToString(HmachSha256DigestBytes);
    }
}
