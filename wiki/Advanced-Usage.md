# Advanced Usage

This guide covers advanced Hackvertor features for power users and complex security testing scenarios.

## Using Hackvertor in Repeater

Hackvertor integrates seamlessly with Burp Repeater for dynamic request modification:

### Method 1: Context Menu Integration

1. Right-click in any Repeater tab
2. Select the **Hackvertor** menu
3. Choose from available options:
   - Send to Hackvertor
   - Apply specific encoding/decoding
   - Auto decode selection

### Method 2: Direct Tag Usage

You can use Hackvertor tags directly in Repeater requests:

```http
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "username": "admin",
  "password": "<@base64><@md5>password123</@md5></@base64>"
}
```

When sent, Hackvertor will:
1. Calculate MD5 of "password123": `482c811da5d5b4bc6d497ffa98491e38`
2. Base64 encode the hash: `NDgyYzgxMWRhNWQ1YjRiYzZkNDk3ZmZhOTg0OTFlMzg=`
3. Send the transformed request to the server

### Method 3: Message Editor Tab

Every request/response viewer in Burp includes a Hackvertor tab:

1. Click the **Hackvertor** tab in any message editor
2. The entire request/response is loaded
3. Add tags around any content
4. View the processed result in real-time

## Complex Tag Nesting

### Understanding Processing Order

Tags are processed from the innermost to the outermost level:

```
<@urlencode><@hex><@uppercase>xss</@uppercase></@hex></@urlencode>
```

Processing steps:
1. `uppercase`: "xss" → "XSS"
2. `hex`: "XSS" → "585353"
3. `urlencode`: "585353" → "585353" (no special chars to encode)

### Practical Nesting Examples

#### SQL Injection Bypass
```
<@hex_entities><@uppercase>union select</@uppercase></@hex_entities>
```
Result: `&#x55;&#x4E;&#x49;&#x4F;&#x4E;&#x20;&#x53;&#x45;&#x4C;&#x45;&#x43;&#x54;`

#### Multi-encoded XSS
```
<@urlencode><@html_entities><script>alert(1)</script></@html_entities></@urlencode>
```
Result: `%26lt%3Bscript%26gt%3Balert%281%29%26lt%3B%2Fscript%26gt%3B`

#### Authentication Token Generation
```
<@base64>user:<@md5>password</@md5>:timestamp</@base64>
```

## Using Multiple Tags in One Input

You can use multiple separate tags in a single input:

```
Username: <@base64>admin</@base64>
Password: <@sha256>secret</@sha256>
Token: <@hex>session123</@hex>
```

Each tag is processed independently.

## Smart Decode Feature

The Smart Decode feature (introduced in v2.0.0) automatically detects and decodes encoded data:

1. Select encoded text
2. Press `Ctrl+Alt+D` or click "Smart Decode"
3. Hackvertor analyzes the encoding and applies appropriate decode tags
4. Supports nested encoding detection

Example:
- Input: `JTNDc2NyaXB0JTNFYWxlcnQoMSklM0MlMkZzY3JpcHQlM0U=`
- Smart Decode detects: Base64 → URL encoding → HTML
- Result: `<script>alert(1)</script>`

## Working with Binary Data

### Compression
```
<@gzip_compress>Large text content here...</@gzip_compress>
```

### Binary to Text Encoding
```
<@base64><@gzip_compress>Compress then encode</@gzip_compress></@base64>
```

## Performance Optimization

### Best Practices

1. **Minimize Nesting Depth**: Deep nesting impacts performance
   ```
   # Good
   <@base64><@md5>data</@md5></@base64>
   
   # Avoid excessive nesting
   <@base64><@hex><@urlencode><@uppercase>...</@uppercase></@urlencode></@hex></@base64>
   ```

2. **Process in Batches**: For large datasets, process chunks separately

3. **Use Appropriate Tags**: Choose the most efficient tag for your needs
   ```
   # Use urlencode_all instead of custom hex encoding
   <@urlencode_all>data</@urlencode_all>
   ```

## Integration with Burp Extensions

Hackvertor can be used with other Burp extensions:

### Intruder Integration
Each Hackvertor tag is available as a payload processor:

1. Set up your Intruder attack
2. Go to Payloads → Payload Processing
3. Add → Invoke Burp extension → Hackvertor
4. Select the desired tag

### Scanner Integration
Use Hackvertor to encode payloads for custom active scan checks.

## Troubleshooting Common Issues

### Tags Not Processing
- Ensure tags are properly closed: `<@tag>content</@tag>`
- Check for typos in tag names
- Verify arguments are properly formatted

### Unexpected Output
- Remember processing order (inner to outer)
- Check for special characters affecting parsing
- Use proper escaping in arguments

### Performance Issues
- Reduce nesting complexity
- Process smaller chunks
- Avoid recursive operations

## Real-World Examples

### JWT Manipulation
```
Header.<@base64url>{"sub":"admin","exp":9999999999}</@base64url>.Signature
```

### SAML Assertion Encoding
```
<@base64><@deflate><Assertion>...</Assertion></@deflate></@base64>
```

### Polyglot Payload
```
<@js_string>'-alert(1)-'</@js_string>
```

## Tips and Tricks

1. **Quick Testing**: Use the Hackvertor tab to test transformations before applying
2. **Save Common Patterns**: Create custom tags for frequently used combinations
3. **Check Output Format**: Some tags produce binary output that may need encoding
4. **Use Variables**: For repeated values in complex transformations
5. **Combine with Macros**: Use Hackvertor in Burp macros for automated processing

---

[Back to Home](Home) | [Next: Custom Tags](Custom-Tags)