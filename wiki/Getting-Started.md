# Getting Started with Hackvertor

## The Hackvertor Interface

Once installed, click on the **Hackvertor** tab in Burp Suite to access the main interface:

### Main Components

1. **Input Area**: Where you enter or paste text to transform
2. **Output Area**: Shows the transformed result in real-time
3. **Tag Categories**: Organized tabs containing different types of tags:
   - Encode
   - Decode
   - Hash
   - String
   - Convert
   - Encrypt
   - And more...
4. **Control Buttons**: Clear, Copy, Paste, and other utility functions

## Basic Usage

### Method 1: Using Tag Buttons

1. Type some text in the input area
2. Select the text you want to transform
3. Click on a tag category (e.g., "Encode")
4. Click on a specific tag button (e.g., "base64")
5. The tag will wrap around your selected text
6. The output will show the transformed result

**Example:**
```
1. Type: hello world
2. Select: hello world
3. Click: Encode → base64
4. Input shows: <@base64>hello world</@base64>
5. Output shows: aGVsbG8gd29ybGQ=
```

### Method 2: Manual Tag Entry

Type tags directly into the input area:

```
<@md5>password123</@md5>
```

Output: `482c811da5d5b4bc6d497ffa98491e38`

### Method 3: Nested Tags

Process data through multiple transformations:

```
<@hex><@base64>secret</@base64></@hex>
```

This will:
1. First encode "secret" to base64: `c2VjcmV0`
2. Then convert to hex: `633256306347563`

## Common First Tasks

### 1. Encode a Password Hash
```
Input: <@sha256>mypassword</@sha256>
Output: 89e01536ac207279409d4de1e5253e01f4a1769e696db0d6062ca9b8f56767c8
```

### 2. URL Encode Parameters
```
Input: <@urlencode>user@example.com</@urlencode>
Output: user%40example.com
```

### 3. Decode Base64
```
Input: <@d_base64>dGVzdDEyMw==</@d_base64>
Output: test123
```

### 4. Multiple Transformations
```
Input: <@hex_entities><@uppercase>xss</@uppercase></@hex_entities>
Output: &#x58;&#x53;&#x53;
```

## Integration with Burp Tools

### Using in Repeater

1. Right-click in any Repeater request/response
2. Select **Hackvertor** from the context menu
3. Choose **Send to Hackvertor** or apply tags directly

### Message Editor Tab

1. In any HTTP message editor, click the **Hackvertor** tab
2. Add tags directly to the request/response
3. See the processed version in real-time

### Context Menu Options

Right-click any selected text in Burp to:
- **Send to Hackvertor**: Open in Hackvertor tab
- **Auto decode**: Attempt automatic decoding
- Apply specific encodings/decodings

## Tips for Beginners

1. **Start Simple**: Try basic tags like `base64`, `hex`, and `md5` first
2. **Use Selection**: Select only the text you want to transform
3. **Preview First**: Always check the output before using in requests
4. **Learn Nesting**: Combine tags for complex transformations
5. **Save Common Patterns**: Create custom tags for repeated operations

## Common Tag Examples

### Encoding Examples
```
<@base64>test</@base64>                → dGVzdA==
<@hex>ABC</@hex>                       → 414243
<@urlencode>hello world</@urlencode>   → hello+world
<@html_entities><tag></@html_entities> → &lt;tag&gt;
```

### Decoding Examples
```
<@d_base64>dGVzdA==</@d_base64>        → test
<@d_hex>414243</@d_hex>                → ABC
<@d_url>hello+world</@d_url>           → hello world
```

### String Manipulation
```
<@uppercase>hello</@uppercase>          → HELLO
<@lowercase>HELLO</@lowercase>          → hello
<@reverse>hello</@reverse>              → olleh
<@length>hello world</@length>          → 11
```

## Next Steps

- Explore the [Tag Reference](Tag-Reference) for all available tags
- Learn about [Advanced Usage](Advanced-Usage) including tag arguments
- Create [Custom Tags](Custom-Tags) for your specific needs

---

[Back to Home](Home) | [Next: Tag Reference](Tag-Reference)