package com.apigeecs.callout;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Apigee Java Callout that constructs a JWT signing string (the unsigned token)
 * per RFC 7515: {@code BASE64URL(header).BASE64URL(payload)}.
 *
 * <p>The resulting signing string is intended to be sent via a Service Callout
 * to an external signing service that will produce the final JWS signature.
 *
 * <p><strong>Zero third-party dependencies</strong> &mdash; JSON is built manually
 * to avoid classloader conflicts on the Apigee runtime.
 *
 * <h3>Configuration Properties</h3>
 * <ul>
 *   <li>{@code header_*} &mdash; Dynamic JOSE header parameters. Any property whose name
 *       starts with the configured prefix (default {@code header_}) is treated as a header
 *       name/value pair. For example, {@code header_alg=RS256} produces {@code {"alg":"RS256"}}.
 *       Properties whose values resolve to null or empty are silently skipped.</li>
 *   <li>{@code header-prefix} &mdash; Override the default prefix for header properties
 *       (default: {@code header_}).</li>
 *   <li>{@code crit_headers} &mdash; Comma-separated list of critical header names to include
 *       in the JOSE {@code "crit"} array. Each listed name must also be present as a header.</li>
 *   <li>{@code payload} &mdash; The JWT claims payload as a JSON string (or a flow variable
 *       reference in curly braces).</li>
 *   <li>{@code output-variable} &mdash; Flow variable to store the signing string
 *       (default: {@code jwt_signing_string}).</li>
 *   <li>{@code header-b64-variable} &mdash; Flow variable to store the Base64URL-encoded header
 *       (default: {@code jwt_header_b64}).</li>
 *   <li>{@code payload-b64-variable} &mdash; Flow variable to store the Base64URL-encoded payload
 *       (default: {@code jwt_payload_b64}).</li>
 *   <li>{@code error-variable} &mdash; Flow variable to store error messages
 *       (default: {@code jwt_error}).</li>
 * </ul>
 *
 * <p>All property values support Apigee flow variable resolution: values wrapped in
 * {@code {curly_braces}} are resolved from the {@link MessageContext} at runtime.
 */
public class JwtSigningStringCallout implements Execution {

    /** Default prefix used to identify JOSE header properties. */
    private static final String DEFAULT_HEADER_PREFIX = "header_";

    /**
     * Pattern matching flow variable references: {@code {variableName}}.
     * Variable names may contain alphanumeric characters, dots, underscores, and hyphens.
     * This avoids matching JSON content like {@code {"key":"value"}}.
     */
    private static final Pattern FLOW_VAR_PATTERN = Pattern.compile("\\{([a-zA-Z][a-zA-Z0-9._-]*)\\}");

    /** Callout properties configured on the Apigee JavaCallout policy. */
    private final Map<String, String> properties;

    /**
     * Constructor invoked by the Apigee gateway.
     *
     * @param properties the policy properties defined in the JavaCallout configuration
     */
    public JwtSigningStringCallout(Map<String, String> properties) {
        this.properties = properties;
    }

    /**
     * Main execution entry point called by the Apigee message processor.
     *
     * @param messageContext  the current message context
     * @param executionContext the execution context
     * @return {@link ExecutionResult#SUCCESS} if the signing string was built,
     *         or {@link ExecutionResult#ABORT} on any error
     */
    @Override
    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        String errorVariable = resolveProperty("error-variable", "jwt_error", messageContext);

        try {
            // --- Determine variable names ---
            String outputVariable = resolveProperty("output-variable", "jwt_signing_string", messageContext);
            String headerB64Variable = resolveProperty("header-b64-variable", "jwt_header_b64", messageContext);
            String payloadB64Variable = resolveProperty("payload-b64-variable", "jwt_payload_b64", messageContext);
            String headerPrefix = resolveProperty("header-prefix", DEFAULT_HEADER_PREFIX, messageContext);

            // --- Build JOSE header ---
            Map<String, String> headerParams = buildJoseHeader(headerPrefix, messageContext);

            if (headerParams.isEmpty()) {
                return abort(messageContext, errorVariable,
                        "No JOSE header parameters found. "
                        + "Configure properties with the prefix '" + headerPrefix + "'.");
            }

            // --- Process crit headers ---
            List<String> critList = processCritHeaders(headerParams, messageContext);

            // --- Build header JSON string ---
            String headerJson = buildHeaderJson(headerParams, critList);

            // --- Resolve and validate payload ---
            String payloadJson = resolvePayload(messageContext);

            // --- Base64URL encode ---
            String headerB64 = base64UrlEncode(headerJson);
            String payloadB64 = base64UrlEncode(payloadJson);
            String signingString = headerB64 + "." + payloadB64;

            // --- Set output variables ---
            messageContext.setVariable(outputVariable, signingString);
            messageContext.setVariable(headerB64Variable, headerB64);
            messageContext.setVariable(payloadB64Variable, payloadB64);

            // Clear any previous error
            messageContext.setVariable(errorVariable, null);

            return ExecutionResult.SUCCESS;

        } catch (IllegalArgumentException e) {
            return abort(messageContext, errorVariable, e.getMessage());
        } catch (Exception e) {
            return abort(messageContext, errorVariable,
                    "Unexpected error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
    }

    /**
     * Builds the JOSE header parameters by collecting all properties that start
     * with the configured prefix. Header properties whose values resolve to null
     * or empty are silently skipped, allowing a superset of headers to be configured
     * while only including those with actual values (e.g., from KVM lookups).
     *
     * @param headerPrefix   the prefix identifying header properties
     * @param messageContext  the message context for resolving flow variables
     * @return an ordered map of header name to value (sorted alphabetically for consistency)
     */
    Map<String, String> buildJoseHeader(String headerPrefix, MessageContext messageContext) {
        Map<String, String> headerParams = new TreeMap<>();

        for (Map.Entry<String, String> entry : properties.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith(headerPrefix)) {
                String headerName = key.substring(headerPrefix.length());
                if (!headerName.isEmpty()) {
                    String resolvedValue = resolveFlowVariables(entry.getValue(), messageContext);
                    if (resolvedValue != null && !resolvedValue.trim().isEmpty()) {
                        headerParams.put(headerName, resolvedValue);
                    }
                }
            }
        }

        return headerParams;
    }

    /**
     * Processes the {@code crit_headers} property: validates that each listed critical
     * header is present in the JOSE header and returns the list of critical header names.
     *
     * @param headerParams   the constructed JOSE header parameters
     * @param messageContext  the message context for resolving flow variables
     * @return list of critical header names, or empty list if none configured
     * @throws IllegalArgumentException if a critical header is not present in the JOSE header
     */
    List<String> processCritHeaders(Map<String, String> headerParams, MessageContext messageContext) {
        List<String> critList = new ArrayList<>();

        String critProperty = properties.get("crit_headers");
        if (critProperty == null || critProperty.trim().isEmpty()) {
            return critList;
        }

        String resolved = resolveFlowVariables(critProperty, messageContext);
        String[] critNames = resolved.split(",");

        for (String name : critNames) {
            String trimmed = name.trim();
            if (!trimmed.isEmpty()) {
                if (!headerParams.containsKey(trimmed)) {
                    throw new IllegalArgumentException(
                            "Critical header '" + trimmed + "' is listed in crit_headers "
                            + "but is not present in the JOSE header.");
                }
                critList.add(trimmed);
            }
        }

        return critList;
    }

    /**
     * Builds a JSON string from the header parameters and optional crit list.
     * JSON is built manually to avoid any third-party library dependencies.
     *
     * @param headerParams the JOSE header key-value pairs
     * @param critList     the list of critical headers (may be empty)
     * @return a valid JSON object string
     */
    String buildHeaderJson(Map<String, String> headerParams, List<String> critList) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;

        for (Map.Entry<String, String> entry : headerParams.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            sb.append("\"").append(jsonEscape(entry.getKey())).append("\"");
            sb.append(":");
            sb.append("\"").append(jsonEscape(entry.getValue())).append("\"");
            first = false;
        }

        if (!critList.isEmpty()) {
            if (!first) {
                sb.append(",");
            }
            sb.append("\"crit\":[");
            for (int i = 0; i < critList.size(); i++) {
                if (i > 0) {
                    sb.append(",");
                }
                sb.append("\"").append(jsonEscape(critList.get(i))).append("\"");
            }
            sb.append("]");
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * Escapes a string for safe inclusion in a JSON value.
     * Handles the characters required by RFC 8259.
     *
     * @param value the raw string
     * @return the JSON-escaped string
     */
    static String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /**
     * Resolves the JWT payload from the configured {@code payload} property.
     * The property value may be a literal JSON string or a flow variable reference.
     * Validates that the resolved payload looks like a JSON object (starts with '{').
     *
     * @param messageContext the message context for resolving flow variables
     * @return the payload JSON string
     * @throws IllegalArgumentException if the payload property is missing or not valid JSON
     */
    String resolvePayload(MessageContext messageContext) {
        String payloadProperty = properties.get("payload");
        if (payloadProperty == null || payloadProperty.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "The 'payload' property is required but was not configured.");
        }

        String resolved = resolveFlowVariables(payloadProperty, messageContext);
        if (resolved == null || resolved.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "The payload resolved to an empty value. "
                    + "Check the flow variable reference in the 'payload' property.");
        }

        // Basic JSON object validation (must start and end with braces)
        String trimmed = resolved.trim();
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) {
            throw new IllegalArgumentException(
                    "The payload is not valid JSON: must be a JSON object starting with '{' and ending with '}'.");
        }

        return resolved;
    }

    /**
     * Encodes the given string using Base64URL encoding (no padding) per RFC 4648 Section 5.
     * Uses a Java 7-compatible implementation (no {@code java.util.Base64}).
     *
     * @param input the string to encode
     * @return the Base64URL-encoded string without padding
     */
    static String base64UrlEncode(String input) {
        byte[] data;
        try {
            data = input.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            // UTF-8 is guaranteed to be available on every JVM
            throw new RuntimeException(e);
        }

        // Standard Base64 alphabet
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        StringBuilder sb = new StringBuilder((data.length * 4 + 2) / 3);

        for (int i = 0; i < data.length; i += 3) {
            int b0 = data[i] & 0xFF;
            int b1 = (i + 1 < data.length) ? (data[i + 1] & 0xFF) : 0;
            int b2 = (i + 2 < data.length) ? (data[i + 2] & 0xFF) : 0;

            sb.append(alphabet.charAt(b0 >> 2));
            sb.append(alphabet.charAt(((b0 & 0x03) << 4) | (b1 >> 4)));

            if (i + 1 < data.length) {
                sb.append(alphabet.charAt(((b1 & 0x0F) << 2) | (b2 >> 6)));
            }
            if (i + 2 < data.length) {
                sb.append(alphabet.charAt(b2 & 0x3F));
            }
        }

        // Convert to URL-safe: replace '+' with '-' and '/' with '_'
        String result = sb.toString();
        result = result.replace('+', '-').replace('/', '_');

        return result;
    }

    /**
     * Resolves a named property, returning the default value if the property is not set.
     *
     * @param propertyName   the property name to look up
     * @param defaultValue   the default value if not configured
     * @param messageContext the message context for resolving flow variables
     * @return the resolved property value
     */
    private String resolveProperty(String propertyName, String defaultValue,
                                   MessageContext messageContext) {
        String value = properties.get(propertyName);
        if (value == null || value.trim().isEmpty()) {
            return defaultValue;
        }
        return resolveFlowVariables(value, messageContext);
    }

    /**
     * Resolves flow variable references in the given string. References are denoted
     * by {@code {variableName}} and are replaced with the corresponding value from the
     * {@link MessageContext}. If the entire string is a single variable reference,
     * the raw variable value is returned (supporting non-string types).
     *
     * @param input          the input string potentially containing flow variable references
     * @param messageContext the message context to resolve variables from
     * @return the input with all flow variable references resolved
     */
    String resolveFlowVariables(String input, MessageContext messageContext) {
        if (input == null) {
            return null;
        }

        // Check if the entire string is a single flow variable reference
        Matcher fullMatch = Pattern.compile("^\\{([a-zA-Z][a-zA-Z0-9._-]*)\\}$").matcher(input.trim());
        if (fullMatch.matches()) {
            String varName = fullMatch.group(1);
            Object value = messageContext.getVariable(varName);
            return value != null ? value.toString() : "";
        }

        // Replace inline variable references
        Matcher matcher = FLOW_VAR_PATTERN.matcher(input);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            String varName = matcher.group(1);
            Object value = messageContext.getVariable(varName);
            String replacement = value != null ? Matcher.quoteReplacement(value.toString()) : "";
            matcher.appendReplacement(sb, replacement);
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * Sets the error variable and returns {@link ExecutionResult#ABORT}.
     *
     * @param messageContext the message context
     * @param errorVariable  the name of the error flow variable
     * @param message        the error message
     * @return {@link ExecutionResult#ABORT}
     */
    private ExecutionResult abort(MessageContext messageContext, String errorVariable,
                                  String message) {
        messageContext.setVariable(errorVariable, message);
        return ExecutionResult.ABORT;
    }
}
