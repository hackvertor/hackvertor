# Hackvertor Tag Store

The Tag Store is a community-driven repository where Hackvertor users can share their custom tags with others. Introduced in version 1.8, it allows for easy distribution and installation of useful custom tags.

## Accessing the Tag Store

### From Hackvertor

1. Open the Hackvertor tab in Burp Suite
2. Go to the menu
3. Click **"View tag store"**
4. Browse available community tags

### On GitHub

Visit the [Tag Store Repository](https://github.com/hackvertor/hackvertor/tree/master/tag-store) to view all available tags.

## Installing Tags from the Store

1. Open the Tag Store viewer in Hackvertor
2. Browse available tags
3. Click **"Install"** next to the tag you want
4. The tag is automatically added to your custom tags
5. The install button becomes disabled once installed

## Contributing to the Tag Store

### Submission Rules

1. **One tag per pull request** - Makes review easier
2. **Single file requirement** - Cannot import multiple files
3. **Folder structure** - Create folder with tag name containing the tag file
4. **Author attribution** - Author property should match your GitHub username
5. **No obfuscation** - Code must be readable and reviewable
6. **No malicious code** - Obviously not allowed
7. **Testing required** - Must test before submission

### How to Submit Your Tag

#### Step 1: Create and Test Your Tag

1. Create a custom tag in Hackvertor
2. Test thoroughly in the Hackvertor interface
3. Ensure it works correctly with various inputs

#### Step 2: Export Your Tag

1. Go to **"List custom tags"**
2. Select your tag
3. Click **"Edit tag"**
4. Click **"Export to tag store"**
5. Copy the generated JSON

#### Step 3: Prepare Your Submission

1. Fork the [Hackvertor repository](https://github.com/hackvertor/hackvertor)
2. Navigate to the `tag-store` folder
3. Create a new folder with your tag name
4. Create a file inside with the same name and appropriate extension
5. Add your tag entry to `tag-store.json`

#### Step 4: Submit Pull Request

1. Commit your changes
2. Create a pull request
3. Provide description of what your tag does
4. Wait for review and approval

### File Structure Example

```
tag-store/
├── tag-store.json
├── my_custom_encoder/
│   └── my_custom_encoder.py
├── another_tag/
│   └── another_tag.js
```

### tag-store.json Format

```json
{
  "tags": [
    {
      "name": "my_custom_encoder",
      "category": "Encode",
      "description": "Encodes data using my custom algorithm",
      "language": "python",
      "author": "yourgithubusername",
      "code": "# Code here or reference to file"
    }
  ]
}
```

## Featured Community Tags

### Popular Tags

Some popular tags from the community include:

- **ean13** - Generate EAN-13 barcodes
- **jwt_decode** - Decode JWT tokens
- **unicode_normalize** - Unicode normalization
- **sql_char** - SQL CHAR() encoding

### Tag Categories

Community tags cover various categories:

- **Encode/Decode** - Custom encoding schemes
- **Crypto** - Cryptographic operations
- **String** - Text manipulation
- **Convert** - Data format conversions
- **Miscellaneous** - Specialized tools

## Quality Guidelines

### Good Tag Characteristics

1. **Clear Purpose** - Does one thing well
2. **Good Documentation** - Clear description and examples
3. **Error Handling** - Handles edge cases gracefully
4. **Performance** - Efficient implementation
5. **Reusability** - Useful for multiple scenarios

### Example: Well-Documented Tag

```python
"""
Tag: custom_b64_variant
Description: Base64 encoding with custom alphabet for obfuscation
Usage: <@custom_b64_variant>data</@custom_b64_variant>
Author: security_researcher
"""

import base64

# Custom alphabet (shuffled base64 chars)
STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
CUSTOM = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210-_"

# Encode using standard base64
b64 = base64.b64encode(input.encode()).decode()

# Translate to custom alphabet
trans = str.maketrans(STANDARD, CUSTOM)
output = b64.translate(trans)
```

## Updating Tags

### Version Control

- Tags can be updated via new pull requests
- Include version notes in PR description
- Maintain backward compatibility when possible

### Bug Fixes

If you find a bug in a community tag:

1. Report it via GitHub issues
2. Submit a fix via pull request
3. Reference the issue in your PR

## Best Practices for Tag Store

1. **Search First** - Check if similar tag exists
2. **Test Thoroughly** - Include edge cases
3. **Document Well** - Clear usage instructions
4. **Follow Standards** - Consistent naming and structure
5. **Engage Community** - Respond to feedback

## Review Process

### What Reviewers Check

1. Code quality and readability
2. Security implications
3. Performance impact
4. Usefulness to community
5. Adherence to submission rules

### Timeline

- Reviews may take time (maintainers have day jobs!)
- Simple tags reviewed faster
- Complex tags need more thorough review
- Be patient and responsive to feedback

## Tips for Successful Submissions

1. **Start Simple** - First submission should be straightforward
2. **Clear Communication** - Explain use cases in PR
3. **Provide Examples** - Show input/output examples
4. **Be Responsive** - Address reviewer feedback promptly
5. **Help Others** - Review and test other submissions

---

[Back to Home](Home) | [Next: Changelog](Changelog)