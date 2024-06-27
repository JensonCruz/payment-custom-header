package com.apigee.gateway.callout;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

public class SignatureGeneratorTest {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        // Test data
        String payload = "{\n" +
                "  \"targetOrigins\": [\n" +
                "    \"https://www.test.com\"\n" +
                "  ],\n" +
                "  \"allowedCardNetworks\": [\n" +
                "    \"VISA\",\n" +
                "    \"MAESTRO\",\n" +
                "    \"MASTERCARD\",\n" +
                "    \"AMEX\",\n" +
                "    \"DISCOVER\",\n" +
                "    \"DINERSCLUB\",\n" +
                "    \"JCB\",\n" +
                "    \"CUP\",\n" +
                "    \"CARTESBANCAIRES\"\n" +
                "  ],\n" +
                "  \"clientVersion\": \"v2.0\"\n" +
                "}";
        String sharedKey = "tFqKXfWq/06qa9GXG/fJ16zNBcIkjjK+xysPrGMS9Sg=";
        String merchantKeyId = "2fbe37a0-306b-4470-9b4c-7705070318c9";
        String requestHost = "apitest.cybersource.com";
        String merchantId = "optus_sandbox";
        String resource = "/microform/v2/sessions/";
        String method = "POST";

        // Generate v-c-date
        String gmtDate = DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneOffset.UTC));
        System.out.println("v-c-date: " + gmtDate);

        // Generate digest
        String digest = generateDigest(payload);
        String digestHeader = "SHA-256=" + digest;
        System.out.println("digest: " + digestHeader);

        // Construct the signature string
        StringBuilder signatureString = new StringBuilder();
        signatureString.append("host: ").append(requestHost).append("\n");
        signatureString.append("date: ").append(gmtDate).append("\n");
        signatureString.append("request-target: ").append(method.toLowerCase()).append(" ").append(resource).append("\n");
        signatureString.append("digest: ").append(digestHeader).append("\n");
        signatureString.append("v-c-merchant-id: ").append(merchantId);

        // Generate HMAC signature
        String signature = generateHMACSHA256Signature(sharedKey, signatureString.toString());
        String signatureHeader = "keyid=\"" + merchantKeyId + "\", algorithm=\"HmacSHA256\", headers=\"host date request-target digest v-c-merchant-id\", signature=\"" + signature + "\"";
        System.out.println("signature: " + signatureHeader);
    }

    private static String generateDigest(String payload) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    private static String generateHMACSHA256Signature(String sharedKey, String validationString)
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
