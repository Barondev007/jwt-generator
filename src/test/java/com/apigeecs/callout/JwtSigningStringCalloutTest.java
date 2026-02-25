package com.apigeecs.callout;

import com.apigee.flow.execution.ExecutionResult;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for {@link JwtSigningStringCallout}.
 * No third-party JSON library is used &mdash; decoded JSON strings are
 * verified with simple string assertions.
 */
public class JwtSigningStringCalloutTest {

    private FakeMessageContext messageContext;
    private FakeExecutionContext executionContext;

    @Before
    public void setUp() {
        messageContext = new FakeMessageContext();
        executionContext = new FakeExecutionContext();
    }

    // ---------------------------------------------------------------
    // Helper methods
    // ---------------------------------------------------------------

    private JwtSigningStringCallout createCallout(Map<String, String> props) {
        return new JwtSigningStringCallout(props);
    }

    private Map<String, String> basicProperties() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("header_typ", "JWT");
        props.put("payload", "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}");
        return props;
    }

    private String base64UrlDecode(String encoded) {
        return new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8);
    }

    // ---------------------------------------------------------------
    // Happy-path tests
    // ---------------------------------------------------------------

    @Test
    public void testBasicSigningStringConstruction() {
        Map<String, String> props = basicProperties();
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);

        assertEquals(ExecutionResult.SUCCESS, result);
        assertNotNull(messageContext.getVariable("jwt_signing_string"));
        assertNotNull(messageContext.getVariable("jwt_header_b64"));
        assertNotNull(messageContext.getVariable("jwt_payload_b64"));
    }

    @Test
    public void testSigningStringFormat() {
        Map<String, String> props = basicProperties();
        JwtSigningStringCallout callout = createCallout(props);

        callout.execute(messageContext, executionContext);

        String signingString = messageContext.getVariable("jwt_signing_string");
        assertNotNull("Signing string should not be null", signingString);

        // Must contain exactly one dot
        String[] parts = signingString.split("\\.");
        assertEquals("Signing string must have exactly two parts", 2, parts.length);

        // Parts must match the individual stored values
        String headerB64 = messageContext.getVariable("jwt_header_b64");
        String payloadB64 = messageContext.getVariable("jwt_payload_b64");
        assertEquals(parts[0], headerB64);
        assertEquals(parts[1], payloadB64);
    }

    @Test
    public void testSigningStringDecodesCorrectly() {
        Map<String, String> props = basicProperties();
        JwtSigningStringCallout callout = createCallout(props);

        callout.execute(messageContext, executionContext);

        String headerB64 = messageContext.getVariable("jwt_header_b64");
        String payloadB64 = messageContext.getVariable("jwt_payload_b64");

        // Decode header — TreeMap produces alphabetical order: alg, typ
        String headerJson = base64UrlDecode(headerB64);
        assertTrue("Header should contain alg", headerJson.contains("\"alg\":\"RS256\""));
        assertTrue("Header should contain typ", headerJson.contains("\"typ\":\"JWT\""));

        // Decode payload — it's passed through as-is
        String payloadJson = base64UrlDecode(payloadB64);
        assertTrue("Payload should contain sub", payloadJson.contains("\"sub\":\"1234567890\""));
        assertTrue("Payload should contain name", payloadJson.contains("\"name\":\"John Doe\""));
        assertTrue("Payload should contain iat", payloadJson.contains("\"iat\":1516239022"));
    }

    // ---------------------------------------------------------------
    // Dynamic header construction tests
    // ---------------------------------------------------------------

    @Test
    public void testDynamicHeaderConstruction() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("header_kid", "my-key-id");
        props.put("header_typ", "JWT");
        props.put("header_x5u", "https://example.com/cert");
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        Map<String, String> header = callout.buildJoseHeader("header_", messageContext);

        assertEquals("RS256", header.get("alg"));
        assertEquals("my-key-id", header.get("kid"));
        assertEquals("JWT", header.get("typ"));
        assertEquals("https://example.com/cert", header.get("x5u"));
    }

    @Test
    public void testCustomHeaderPrefix() {
        Map<String, String> props = new HashMap<>();
        props.put("header-prefix", "jose_");
        props.put("jose_alg", "ES256");
        props.put("jose_typ", "JWT");
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);
        assertEquals(ExecutionResult.SUCCESS, result);

        String headerJson = base64UrlDecode(messageContext.<String>getVariable("jwt_header_b64"));
        assertTrue(headerJson.contains("\"alg\":\"ES256\""));
        assertTrue(headerJson.contains("\"typ\":\"JWT\""));
    }

    @Test
    public void testHeaderPropertyWithEmptyNameIgnored() {
        Map<String, String> props = new HashMap<>();
        props.put("header_", "should-be-ignored");
        props.put("header_alg", "RS256");
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        Map<String, String> header = callout.buildJoseHeader("header_", messageContext);
        assertEquals(1, header.size());
        assertEquals("RS256", header.get("alg"));
    }

    @Test
    public void testHeaderWithNullFlowVariableSkipped() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("header_kid", "{private.jwt.header.kid}");
        props.put("header_x5u", "{private.jwt.header.x5u}");
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        // Only kid is set; x5u is not in the context (simulates missing KVM key)
        messageContext.setVariable("private.jwt.header.kid", "my-key-id");

        ExecutionResult result = callout.execute(messageContext, executionContext);
        assertEquals(ExecutionResult.SUCCESS, result);

        String headerJson = base64UrlDecode(messageContext.<String>getVariable("jwt_header_b64"));
        assertTrue("Header should contain alg", headerJson.contains("\"alg\":\"RS256\""));
        assertTrue("Header should contain kid", headerJson.contains("\"kid\":\"my-key-id\""));
        assertFalse("x5u should be absent when flow variable is null", headerJson.contains("\"x5u\""));
    }

    @Test
    public void testHeaderWithEmptyFlowVariableSkipped() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("header_kid", "{private.jwt.header.kid}");
        props.put("header_x5u", "{private.jwt.header.x5u}");
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        messageContext.setVariable("private.jwt.header.kid", "my-key-id");
        messageContext.setVariable("private.jwt.header.x5u", "");

        ExecutionResult result = callout.execute(messageContext, executionContext);
        assertEquals(ExecutionResult.SUCCESS, result);

        String headerJson = base64UrlDecode(messageContext.<String>getVariable("jwt_header_b64"));
        assertTrue(headerJson.contains("\"alg\":\"RS256\""));
        assertTrue(headerJson.contains("\"kid\":\"my-key-id\""));
        assertFalse("x5u should be absent when flow variable is empty", headerJson.contains("\"x5u\""));
    }

    @Test
    public void testAllHeadersFromKvmPresent() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "{private.jwt.header.alg}");
        props.put("header_typ", "{private.jwt.header.typ}");
        props.put("header_kid", "{private.jwt.header.kid}");
        props.put("header_x5u", "{private.jwt.header.x5u}");
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        messageContext.setVariable("private.jwt.header.alg", "RS256");
        messageContext.setVariable("private.jwt.header.typ", "JWT");
        messageContext.setVariable("private.jwt.header.kid", "key-123");
        messageContext.setVariable("private.jwt.header.x5u", "https://example.com/cert");

        ExecutionResult result = callout.execute(messageContext, executionContext);
        assertEquals(ExecutionResult.SUCCESS, result);

        String headerJson = base64UrlDecode(messageContext.<String>getVariable("jwt_header_b64"));
        assertTrue(headerJson.contains("\"alg\":\"RS256\""));
        assertTrue(headerJson.contains("\"typ\":\"JWT\""));
        assertTrue(headerJson.contains("\"kid\":\"key-123\""));
        assertTrue(headerJson.contains("\"x5u\":\"https://example.com/cert\""));
    }

    // ---------------------------------------------------------------
    // Crit header validation tests
    // ---------------------------------------------------------------

    @Test
    public void testCritHeadersPositive() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("header_typ", "JWT");
        props.put("header_x5u", "https://example.com/cert");
        props.put("crit_headers", "x5u");
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);
        assertEquals(ExecutionResult.SUCCESS, result);

        String headerJson = base64UrlDecode(messageContext.<String>getVariable("jwt_header_b64"));
        assertTrue("Header should contain crit array", headerJson.contains("\"crit\":[\"x5u\"]"));
    }

    @Test
    public void testCritHeadersMultiple() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("header_x5u", "https://example.com/cert");
        props.put("header_custom1", "val1");
        props.put("crit_headers", "x5u, custom1");
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);
        assertEquals(ExecutionResult.SUCCESS, result);

        String headerJson = base64UrlDecode(messageContext.<String>getVariable("jwt_header_b64"));
        assertTrue("Header should contain crit array", headerJson.contains("\"crit\":[\"x5u\",\"custom1\"]"));
    }

    @Test
    public void testCritHeaderMissing_ReturnsAbort() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("crit_headers", "x5u");
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);

        assertEquals(ExecutionResult.ABORT, result);
        String error = messageContext.getVariable("jwt_error");
        assertTrue(error.contains("Critical header 'x5u' is listed in crit_headers but is not present"));
    }

    @Test
    public void testEmptyCritHeaders_NoError() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("crit_headers", "");
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);
        assertEquals(ExecutionResult.SUCCESS, result);
    }

    @Test
    public void testNoCritHeadersProperty_NoError() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);
        assertEquals(ExecutionResult.SUCCESS, result);
        assertNull(messageContext.getVariable("jwt_error"));
    }

    // ---------------------------------------------------------------
    // Flow variable resolution tests
    // ---------------------------------------------------------------

    @Test
    public void testFlowVariableResolutionInHeaderValues() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("header_kid", "{my.key.id}");
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        messageContext.setVariable("my.key.id", "resolved-key-id-123");

        ExecutionResult result = callout.execute(messageContext, executionContext);
        assertEquals(ExecutionResult.SUCCESS, result);

        String headerJson = base64UrlDecode(messageContext.<String>getVariable("jwt_header_b64"));
        assertTrue(headerJson.contains("\"kid\":\"resolved-key-id-123\""));
    }

    @Test
    public void testFlowVariableResolutionInPayload() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("payload", "{jwt.claims}");
        JwtSigningStringCallout callout = createCallout(props);

        String claimsJson = "{\"sub\":\"resolved-subject\",\"iss\":\"my-issuer\"}";
        messageContext.setVariable("jwt.claims", claimsJson);

        ExecutionResult result = callout.execute(messageContext, executionContext);
        assertEquals(ExecutionResult.SUCCESS, result);

        String payloadJson = base64UrlDecode(messageContext.<String>getVariable("jwt_payload_b64"));
        assertTrue(payloadJson.contains("\"sub\":\"resolved-subject\""));
        assertTrue(payloadJson.contains("\"iss\":\"my-issuer\""));
    }

    @Test
    public void testFlowVariableResolutionInline() {
        JwtSigningStringCallout callout = createCallout(new HashMap<>());

        messageContext.setVariable("prefix", "hello");
        messageContext.setVariable("suffix", "world");

        String result = callout.resolveFlowVariables("{prefix}-{suffix}", messageContext);
        assertEquals("hello-world", result);
    }

    @Test
    public void testFlowVariableResolutionMissingVariable() {
        JwtSigningStringCallout callout = createCallout(new HashMap<>());

        String result = callout.resolveFlowVariables("{missing}", messageContext);
        assertEquals("", result);
    }

    @Test
    public void testFlowVariableResolutionNoVariables() {
        JwtSigningStringCallout callout = createCallout(new HashMap<>());

        String result = callout.resolveFlowVariables("plain-text", messageContext);
        assertEquals("plain-text", result);
    }

    @Test
    public void testFlowVariableResolutionNull() {
        JwtSigningStringCallout callout = createCallout(new HashMap<>());

        String result = callout.resolveFlowVariables(null, messageContext);
        assertNull(result);
    }

    // ---------------------------------------------------------------
    // Base64URL encoding tests
    // ---------------------------------------------------------------

    @Test
    public void testBase64UrlEncodeNoPadding() {
        String encoded = JwtSigningStringCallout.base64UrlEncode("a");
        assertFalse("Base64URL must not contain padding", encoded.contains("="));
        assertEquals("YQ", encoded);
    }

    @Test
    public void testBase64UrlEncodeUrlSafe() {
        String encoded = JwtSigningStringCallout.base64UrlEncode("{\"alg\":\"RS256\"}");
        assertFalse("Base64URL must not contain '+'", encoded.contains("+"));
        assertFalse("Base64URL must not contain '/'", encoded.contains("/"));
    }

    @Test
    public void testBase64UrlEncodeRoundTrip() {
        String original = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String encoded = JwtSigningStringCallout.base64UrlEncode(original);
        String decoded = base64UrlDecode(encoded);
        assertEquals(original, decoded);
    }

    @Test
    public void testBase64UrlEncodeKnownValue() {
        String input = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
        String encoded = JwtSigningStringCallout.base64UrlEncode(input);
        String decoded = base64UrlDecode(encoded);
        assertEquals(input, decoded);
    }

    @Test
    public void testBase64UrlEncodeEmptyString() {
        String encoded = JwtSigningStringCallout.base64UrlEncode("");
        assertEquals("", encoded);
    }

    // ---------------------------------------------------------------
    // JSON builder tests
    // ---------------------------------------------------------------

    @Test
    public void testBuildHeaderJson_Simple() {
        Map<String, String> params = new java.util.TreeMap<>();
        params.put("alg", "RS256");
        params.put("typ", "JWT");
        JwtSigningStringCallout callout = createCallout(new HashMap<>());

        String json = callout.buildHeaderJson(params, new ArrayList<>());
        assertEquals("{\"alg\":\"RS256\",\"typ\":\"JWT\"}", json);
    }

    @Test
    public void testBuildHeaderJson_WithCrit() {
        Map<String, String> params = new java.util.TreeMap<>();
        params.put("alg", "RS256");
        params.put("x5u", "https://example.com");
        JwtSigningStringCallout callout = createCallout(new HashMap<>());

        java.util.List<String> crit = new ArrayList<>();
        crit.add("x5u");

        String json = callout.buildHeaderJson(params, crit);
        assertTrue(json.contains("\"crit\":[\"x5u\"]"));
        assertTrue(json.contains("\"alg\":\"RS256\""));
        assertTrue(json.contains("\"x5u\":\"https://example.com\""));
    }

    @Test
    public void testJsonEscape_SpecialChars() {
        assertEquals("hello\\\"world", JwtSigningStringCallout.jsonEscape("hello\"world"));
        assertEquals("back\\\\slash", JwtSigningStringCallout.jsonEscape("back\\slash"));
        assertEquals("new\\nline", JwtSigningStringCallout.jsonEscape("new\nline"));
        assertEquals("tab\\there", JwtSigningStringCallout.jsonEscape("tab\there"));
    }

    @Test
    public void testJsonEscape_Null() {
        assertEquals("", JwtSigningStringCallout.jsonEscape(null));
    }

    @Test
    public void testJsonEscape_NoEscaping() {
        assertEquals("simple", JwtSigningStringCallout.jsonEscape("simple"));
        assertEquals("https://example.com/path", JwtSigningStringCallout.jsonEscape("https://example.com/path"));
    }

    // ---------------------------------------------------------------
    // Error scenario tests
    // ---------------------------------------------------------------

    @Test
    public void testMissingPayload_ReturnsAbort() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);

        assertEquals(ExecutionResult.ABORT, result);
        String error = messageContext.getVariable("jwt_error");
        assertTrue(error.contains("'payload' property is required"));
    }

    @Test
    public void testEmptyPayload_ReturnsAbort() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("payload", "");
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);

        assertEquals(ExecutionResult.ABORT, result);
        String error = messageContext.getVariable("jwt_error");
        assertTrue(error.contains("'payload' property is required"));
    }

    @Test
    public void testInvalidPayloadJson_ReturnsAbort() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("payload", "this is not json");
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);

        assertEquals(ExecutionResult.ABORT, result);
        String error = messageContext.getVariable("jwt_error");
        assertTrue(error.contains("not valid JSON"));
    }

    @Test
    public void testNoHeaderProperties_ReturnsAbort() {
        Map<String, String> props = new HashMap<>();
        props.put("payload", "{\"sub\":\"test\"}");
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);

        assertEquals(ExecutionResult.ABORT, result);
        String error = messageContext.getVariable("jwt_error");
        assertTrue(error.contains("No JOSE header parameters found"));
    }

    @Test
    public void testPayloadFlowVariableResolvesToEmpty_ReturnsAbort() {
        Map<String, String> props = new HashMap<>();
        props.put("header_alg", "RS256");
        props.put("payload", "{empty.var}");
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);

        assertEquals(ExecutionResult.ABORT, result);
        String error = messageContext.getVariable("jwt_error");
        assertTrue(error.contains("payload resolved to an empty value"));
    }

    // ---------------------------------------------------------------
    // Custom output variable names
    // ---------------------------------------------------------------

    @Test
    public void testCustomOutputVariableNames() {
        Map<String, String> props = basicProperties();
        props.put("output-variable", "custom.signing.string");
        props.put("header-b64-variable", "custom.header");
        props.put("payload-b64-variable", "custom.payload");
        props.put("error-variable", "custom.error");
        JwtSigningStringCallout callout = createCallout(props);

        ExecutionResult result = callout.execute(messageContext, executionContext);

        assertEquals(ExecutionResult.SUCCESS, result);
        assertNotNull(messageContext.getVariable("custom.signing.string"));
        assertNotNull(messageContext.getVariable("custom.header"));
        assertNotNull(messageContext.getVariable("custom.payload"));
        assertNull(messageContext.getVariable("custom.error"));
    }

    @Test
    public void testErrorClearedOnSuccess() {
        Map<String, String> props = basicProperties();
        JwtSigningStringCallout callout = createCallout(props);

        messageContext.setVariable("jwt_error", "old error");

        ExecutionResult result = callout.execute(messageContext, executionContext);

        assertEquals(ExecutionResult.SUCCESS, result);
        assertNull(messageContext.getVariable("jwt_error"));
    }

    @Test
    public void testDefaultOutputVariableNames() {
        Map<String, String> props = basicProperties();
        JwtSigningStringCallout callout = createCallout(props);

        callout.execute(messageContext, executionContext);

        assertNotNull(messageContext.getVariable("jwt_signing_string"));
        assertNotNull(messageContext.getVariable("jwt_header_b64"));
        assertNotNull(messageContext.getVariable("jwt_payload_b64"));
    }
}
