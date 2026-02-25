package com.apigeecs.callout;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
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
            JSONObject joseHeader = buildJoseHeader(headerPrefix, messageContext);

            if (joseHeader.length() == 0) {
                return abort(messageContext, errorVariable,
                        "No JOSE header parameters found. "
                        + "Configure properties with the prefix '" + headerPrefix + "'.");
            }

            // --- Process crit headers ---
            processCritHeaders(joseHeader, messageContext);

            // --- Resolve and validate payload ---
            String payloadJson = resolvePayload(messageContext);

            // --- Base64URL encode ---
            String headerB64 = base64UrlEncode(joseHeader.toString());
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
     * Builds the JOSE header JSON object by collecting all properties that start
     * with the configured prefix. Header properties whose values resolve to null
     * or empty are silently skipped, allowing a superset of headers to be configured
     * while only including those with actual values (e.g., from KVM lookups).
     *
     * @param headerPrefix   the prefix identifying header properties
     * @param messageContext  the message context for resolving flow variables
     * @return a {@link JSONObject} containing the JOSE header parameters
     */
    JSONObject buildJoseHeader(String headerPrefix, MessageContext messageContext) {
        // Use TreeMap for consistent ordering in tests
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

        JSONObject header = new JSONObject();
        for (Map.Entry<String, String> entry : headerParams.entrySet()) {
            header.put(entry.getKey(), entry.getValue());
        }
        return header;
    }

    /**
     * Processes the {@code crit_headers} property: validates that each listed critical
     * header is present in the JOSE header, then adds the {@code "crit"} array.
     *
     * @param joseHeader     the constructed JOSE header (modified in place)
     * @param messageContext  the message context for resolving flow variables
     * @throws IllegalArgumentException if a critical header is not present in the JOSE header
     */
    void processCritHeaders(JSONObject joseHeader, MessageContext messageContext) {
        String critProperty = properties.get("crit_headers");
        if (critProperty == null || critProperty.trim().isEmpty()) {
            return;
        }

        String resolved = resolveFlowVariables(critProperty, messageContext);
        String[] critNames = resolved.split(",");
        List<String> critList = new ArrayList<>();

        for (String name : critNames) {
            String trimmed = name.trim();
            if (!trimmed.isEmpty()) {
                if (!joseHeader.has(trimmed)) {
                    throw new IllegalArgumentException(
                            "Critical header '" + trimmed + "' is listed in crit_headers "
                            + "but is not present in the JOSE header.");
                }
                critList.add(trimmed);
            }
        }

        if (!critList.isEmpty()) {
            joseHeader.put("crit", critList);
        }
    }

    /**
     * Resolves the JWT payload from the configured {@code payload} property.
     * The property value may be a literal JSON string or a flow variable reference.
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

        // Validate that the payload is valid JSON
        try {
            new JSONObject(resolved);
        } catch (JSONException e) {
            throw new IllegalArgumentException(
                    "The payload is not valid JSON: " + e.getMessage());
        }

        return resolved;
    }

    /**
     * Encodes the given string using Base64URL encoding (no padding) per RFC 4648 Section 5.
     *
     * @param input the string to encode
     * @return the Base64URL-encoded string without padding
     */
    static String base64UrlEncode(String input) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(input.getBytes(StandardCharsets.UTF_8));
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

    /** Prefix indicating a property value is a flow variable name to be resolved at runtime. */
    private static final String REF_PREFIX = "ref:";

    /**
     * Resolves flow variable references in the given string. Supports two modes:
     * <ul>
     *   <li><b>{@code ref:variableName}</b> &mdash; The value after {@code ref:} is treated as a
     *       flow variable name and looked up directly from the {@link MessageContext}.
     *       This avoids relying on Apigee's property-level variable resolution.</li>
     *   <li><b>{@code {variableName}}</b> &mdash; Inline references wrapped in curly braces
     *       are replaced with the corresponding value from the {@link MessageContext}.</li>
     * </ul>
     *
     * @param input          the input string potentially containing flow variable references
     * @param messageContext the message context to resolve variables from
     * @return the input with all flow variable references resolved
     */
    String resolveFlowVariables(String input, MessageContext messageContext) {
        if (input == null) {
            return null;
        }

        // Support "ref:variableName" — direct flow variable lookup
        if (input.startsWith(REF_PREFIX)) {
            String varName = input.substring(REF_PREFIX.length()).trim();
            if (!varName.isEmpty()) {
                Object value = messageContext.getVariable(varName);
                return value != null ? value.toString() : "";
            }
            return "";
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
