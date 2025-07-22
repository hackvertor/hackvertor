# Global Variables

Global variables in Hackvertor allow you to store and reuse values across multiple transformations and tags.

## Creating Global Variables

### Via Menu

1. Go to Hackvertor menubar
2. Click **"Global variables"**
3. Enter variable name (without $ prefix)
4. Enter variable value
5. Click **"Create/Update variable"**

### Via Tags

You can also set variables directly in your tag expressions:

```
<@set_variable1(true)>value_to_store</@set_variable1>
```

## Using Global Variables

### Basic Usage

Reference variables using the `$` prefix:

```
$myVariable
```

### In Transformations

```
Input: <@base64>$username:$password</@base64>
```

If `$username` is "admin" and `$password` is "secret", this produces the base64 encoding of "admin:secret".

### With Tags

Variables can be used as tag inputs:

```
<@md5>$secretKey</@md5>
```

## Variable Management

### Editing Variables

1. Menu → **"Global variables"**
2. Select the variable from the list
3. Click **"Edit"**
4. Modify the value
5. Click **"Create/Update variable"**

### Viewing All Variables

The Global Variables dialog shows:
- Variable name
- Current value
- Options to edit or delete

### Deleting Variables

1. Select the variable
2. Click **"Delete"**
3. Confirm deletion

## Variable Scopes

### Session Variables
Variables persist throughout your Burp Suite session but are lost when Burp closes.

### Tag Variables
Variables set using `set_variable` tags are available immediately:

```
<@set_variable1(true)>myValue</@set_variable1>
Later use: <@get_variable1/>
```

## Advanced Variable Usage

### Dynamic Values

Variables can store results of tag operations:

```
<@set_variable1(true)><@timestamp/></@set_variable1>
```

### Concatenation

Combine variables with static text:

```
Authorization: Bearer $token
User-Agent: $userAgent
```

### In Custom Tags

Access global variables in custom tag code:

```python
# Python custom tag
import hackvertor
token = hackvertor.getVariable("authToken")
output = "Bearer " + token
```

## Common Use Cases

### Authentication Tokens

Store frequently used tokens:
```
Variable: authToken
Value: eyJhbGciOiJIUzI1NiIs...
Usage: Authorization: Bearer $authToken
```

### Test Data

Store test payloads:
```
Variable: xssPayload
Value: <script>alert(1)</script>
Usage: <@html_entities>$xssPayload</@html_entities>
```

### Configuration Values

Store environment-specific values:
```
Variable: apiEndpoint
Value: https://api.example.com/v2
Usage: $apiEndpoint/users
```

### Session Management

Store session identifiers:
```
Variable: sessionId
Value: ABCD1234567890
Usage: Cookie: PHPSESSID=$sessionId
```

## Variable Interpolation

Variables are replaced before tag processing:

```
Input: <@uppercase>Hello $name</@uppercase>
If $name = "world"
Process: <@uppercase>Hello world</@uppercase>
Output: HELLO WORLD
```

## Best Practices

1. **Naming Convention**: Use descriptive names
   - Good: `$apiKey`, `$userToken`, `$testEmail`
   - Bad: `$var1`, `$x`, `$temp`

2. **Value Updates**: Update variables when tokens expire

3. **Security**: Don't store sensitive production credentials

4. **Documentation**: Keep notes on what each variable contains

5. **Cleanup**: Remove unused variables regularly

## Limitations

- Variables are not persisted between Burp sessions
- Variable names cannot contain spaces or special characters
- Values are stored as strings
- Large values may impact performance

## Examples

### Multi-step Authentication
```
Step 1: <@set_variable1(true)><@base64>user:pass</@base64></@set_variable1>
Step 2: Authorization: Basic <@get_variable1/>
```

### Dynamic Payload Generation
```
$timestamp = <@timestamp/>
$nonce = <@md5>$timestamp:$secretKey</@md5>
Request: api_key=$apiKey&nonce=$nonce&timestamp=$timestamp
```

### Reusable Encoding Chains
```
$encoded = <@base64><@gzip>$payload</@gzip></@base64>
Use in multiple requests: data=$encoded
```

## Tips

- Use meaningful variable names for clarity
- Document complex variable usage
- Test variable substitution before using in attacks
- Consider variable scope when designing tests
- Update variables as part of your testing workflow

---

[Back to Home](Home) | [Next: Tag Store](Tag-Store)