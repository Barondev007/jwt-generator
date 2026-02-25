# JWT Signing String Callout for Apigee

An Apigee Java Callout that constructs a JWT signing string (`header.payload`) per RFC 7515, intended for use with an external signing service.

## Building

```bash
mvn clean package
```

The shaded JAR will be in `target/jwt-signing-string-callout-1.0.0.jar`. Copy it to your Apigee proxy's `apiproxy/resources/java/` directory.

You also need the `json-20231013.jar` dependency (bundled by the shade plugin).

## Sample Apigee Policy Configuration

```xml
<JavaCallout name="JC-BuildJwtSigningString">
    <Properties>
        <!-- JOSE Header parameters (prefix: header_) -->
        <Property name="header_alg">RS256</Property>
        <Property name="header_typ">JWT</Property>
        <Property name="header_kid">{private.signing.key.id}</Property>
        <Property name="header_x5u">https://example.com/certs</Property>

        <!-- Critical headers (comma-separated) -->
        <Property name="crit_headers">x5u</Property>

        <!-- JWT payload from a flow variable -->
        <Property name="payload">{jwt.claims.json}</Property>

        <!-- Optional: custom output variable names -->
        <Property name="output-variable">jwt_signing_string</Property>
        <Property name="header-b64-variable">jwt_header_b64</Property>
        <Property name="payload-b64-variable">jwt_payload_b64</Property>
        <Property name="error-variable">jwt_error</Property>
    </Properties>
    <ClassName>com.apigeecs.callout.JwtSigningStringCallout</ClassName>
    <ResourceURL>java://jwt-signing-string-callout-1.0.0.jar</ResourceURL>
</JavaCallout>
```

### Using with a Service Callout

After the Java Callout executes, use a Service Callout to send the signing string to your external signing service:

```xml
<ServiceCallout name="SC-SignJwt">
    <Request>
        <Set>
            <Payload contentType="application/json">
                {"signing_input": "{jwt_signing_string}"}
            </Payload>
        </Set>
    </Request>
    <Response>signing-service-response</Response>
    <HTTPTargetConnection>
        <URL>https://signing-service.example.com/sign</URL>
    </HTTPTargetConnection>
</ServiceCallout>
```

### Fault Rule for Errors

```xml
<FaultRule name="JwtSigningStringError">
    <Condition>jwt_error != null</Condition>
    <Step>
        <Name>AM-JwtError</Name>
    </Step>
</FaultRule>
```

## Configuration Reference

| Property | Required | Default | Description |
|---|---|---|---|
| `header_*` | Yes (at least one) | - | JOSE header parameters. The part after the prefix becomes the header name. |
| `header-prefix` | No | `header_` | Prefix for identifying header properties. |
| `crit_headers` | No | - | Comma-separated list of critical header names. Each must exist in the header. |
| `payload` | Yes | - | JWT claims as a JSON string or flow variable reference. |
| `output-variable` | No | `jwt_signing_string` | Flow variable for the `header.payload` signing string. |
| `header-b64-variable` | No | `jwt_header_b64` | Flow variable for the Base64URL-encoded header. |
| `payload-b64-variable` | No | `jwt_payload_b64` | Flow variable for the Base64URL-encoded payload. |
| `error-variable` | No | `jwt_error` | Flow variable for error messages on failure. |

## Flow Variable Resolution

All property values support Apigee flow variable references using curly braces. For example:

- `{request.header.x-key-id}` resolves to the value of the `x-key-id` request header
- `{private.my.secret}` resolves to a private flow variable
- `prefix-{variable}-suffix` supports inline resolution within a string

## Running Tests

```bash
mvn test
```
