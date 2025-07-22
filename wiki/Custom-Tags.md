# Creating Custom Tags

Hackvertor allows you to extend its functionality by creating custom tags in various programming languages.

## Supported Languages

- **Python** (most popular)
- **JavaScript** (full support as of v1.8.6)
- **Java**
- **Groovy**

## Creating a Custom Tag

### Step 1: Open Tag Creator

1. Go to the Hackvertor tab
2. Click the menu bar
3. Select **"Create custom tag"**

### Step 2: Configure Tag Properties

Fill in the following fields:

- **Tag name**: Name of your tag (e.g., `my_encoder`)
- **Tag category**: Where the tag appears (Encode, Decode, String, etc.)
- **Description**: Brief description of what the tag does
- **Language**: Select Python, JavaScript, Java, or Groovy
- **Code**: Your tag implementation

### Step 3: Tag Code Structure

All custom tags must:
1. Read from the `input` variable
2. Write to the `output` variable
3. Access arguments via `arg1`, `arg2`, etc.

## Python Custom Tags

### Basic Example
```python
# Reverse and uppercase
output = input[::-1].upper()
```

### With Arguments
```python
# Tag usage: <@custom_repeat(3, '-')>test</@custom_repeat>
# Output: test-test-test
count = int(arg1)
separator = arg2
output = separator.join([input] * count)
```

### Using Libraries
```python
import base64
import hashlib

# Custom encoding chain
hashed = hashlib.sha256(input.encode()).hexdigest()
output = base64.b64encode(hashed.encode()).decode()
```

### AI-Powered Python Tags (v2.0.12+)
```python
# Use AI to process input
# Tag name: ai_summarize
# Description: Uses AI to summarize text
output = ai_prompt("Summarize this text in one sentence: " + input)
```

## JavaScript Custom Tags

### Basic Example
```javascript
// ROT13 implementation
output = input.replace(/[a-zA-Z]/g, function(c) {
    return String.fromCharCode(
        (c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26
    );
});
```

### With Arguments
```javascript
// Tag usage: <@js_repeat(3, '|')>X</@js_repeat>
// Output: X|X|X
var count = parseInt(arg1);
var separator = arg2;
var result = [];
for (var i = 0; i < count; i++) {
    result.push(input);
}
output = result.join(separator);
```

## Java Custom Tags

### Basic Example
```java
// Simple reversal
StringBuilder sb = new StringBuilder(input);
output = sb.reverse().toString();
```

### With Arguments
```java
// Tag usage: <@java_pad(10, '0')>42</@java_pad>
// Output: 0000000042
int length = Integer.parseInt(arg1);
String padChar = arg2;
output = input;
while (output.length() < length) {
    output = padChar + output;
}
```

## Groovy Custom Tags

### Basic Example
```groovy
// Word count
def words = input.split(/\s+/)
output = words.size().toString()
```

### With Regular Expressions
```groovy
// Extract emails
def pattern = ~/[\w._%+-]+@[\w.-]+\.[A-Za-z]{2,}/
def matches = input.findAll(pattern)
output = matches.join(", ")
```

## Managing Custom Tags

### Listing Tags
1. Menu → **"List custom tags"**
2. View all your custom tags
3. See tag names, categories, and languages

### Editing Tags
1. Menu → **"List custom tags"**
2. Select the tag to edit
3. Click **"Edit tag"**
4. Modify and save

### Deleting Tags
1. Menu → **"List custom tags"**
2. Select the tag to delete
3. Click **"Delete tag"**

### Exporting Tags
1. Edit the custom tag
2. Click **"Export to tag store"**
3. Save the JSON for sharing

## AI Features (v2.0.12+)

### Learn from Repeater
Hackvertor can analyze encoding patterns from Repeater requests:

1. Make requests with encoded parameters in Repeater
2. Hackvertor learns the encoding pattern
3. Automatically generates Python custom tags

### AI-Generated Tags
Create tags using natural language:

1. Menu → **"Create custom tag"**
2. Describe what you want in the AI prompt
3. Provide input/output examples
4. Hackvertor generates the code

### Code Summarization
When creating custom tags, Hackvertor can:
- Automatically summarize what your code does
- Generate descriptions for complex tags
- Help document your custom tags

## Best Practices

### Error Handling
```python
try:
    # Your code here
    output = process_input(input)
except Exception as e:
    output = "Error: " + str(e)
```

### Input Validation
```python
if not input:
    output = "Error: Empty input"
    return

if len(input) > 10000:
    output = "Error: Input too large"
    return
```

### Performance
```python
# Bad - String concatenation in loop
result = ""
for char in input:
    result += process(char)

# Good - Use join
result = ''.join(process(char) for char in input)
output = result
```

## Example Custom Tags

### URL Parameter Extractor
```python
import re
# Extract all URL parameters
params = re.findall(r'(\w+)=([^&]+)', input)
output = '\n'.join(f'{k}: {v}' for k, v in params)
```

### Custom Base Encoding
```javascript
// Base62 encoding
var charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
var result = '';
var num = parseInt(input);
while (num > 0) {
    result = charset[num % 62] + result;
    num = Math.floor(num / 62);
}
output = result || '0';
```

### Time-based Token
```python
import time
import hashlib

timestamp = str(int(time.time()))
combined = input + ":" + timestamp
output = hashlib.md5(combined.encode()).hexdigest() + ":" + timestamp
```

## Debugging Tips

1. Use print statements (they appear in Burp's extension output)
2. Test with simple inputs first
3. Handle edge cases (empty input, special characters)
4. Validate arguments before using them
5. Return meaningful error messages

---

[Back to Home](Home) | [Next: Global Variables](Global-Variables)