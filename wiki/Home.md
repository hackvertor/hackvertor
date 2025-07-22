# Hackvertor Wiki

![Hackvertor Logo](https://github.com/hackvertor/hackvertor/blob/master/src/main/resources/images/logo-light.png)

Hackvertor is a tag-based conversion tool written in Java, implemented as a Burp Suite extension. It provides a powerful and flexible way to encode, decode, hash, and transform data during security testing.

## What is Hackvertor?

Hackvertor uses a tag-based system for data transformation. Tags are constructed as follows:
- Basic format: `<@tagname>content</@tagname>`
- The @ symbol identifies it as a Hackvertor tag
- Tags can be nested for complex transformations
- Processing occurs from innermost to outermost tags

### Tag Types

1. **Simple tags**: `<@base64>test</@base64>` → `dGVzdA==`
2. **Tags with arguments**: `<@find("\\w")>abc</@find>`
   - String arguments: double quotes `"string"` or single quotes `'string'`
   - Boolean arguments: `true` or `false`
   - Numeric arguments: numbers including hex

## Quick Start

1. Install Hackvertor from the BApp Store in Burp Suite
2. Navigate to the Hackvertor tab
3. Type or paste text in the input area
4. Select text and click a tag button or type tags manually
5. View the transformed output in real-time

## Example

```
Input:  <@base64><@uppercase>hello world</@uppercase></@base64>
Process: 
  1. uppercase: "hello world" → "HELLO WORLD"
  2. base64: "HELLO WORLD" → "SEVMTE8gV09STEA="
Output: SEVMTE8gV09STEA=
```

## Wiki Contents

- [Installation Guide](Installation) - How to install and set up Hackvertor
- [Getting Started](Getting-Started) - Basic usage and interface overview
- [Tag Reference](Tag-Reference) - Complete list of available tags with examples
- [Advanced Usage](Advanced-Usage) - Nested tags, repeater integration, and complex transformations
- [Custom Tags](Custom-Tags) - Creating and managing custom tags
- [Global Variables](Global-Variables) - Using variables across transformations
- [Tag Store](Tag-Store) - Community-contributed tags
- [Changelog](Changelog) - Version history and updates

## Latest Features (v2.0.12)

- **AI Features**: 
  - Learn encoding patterns from Repeater requests
  - AI-generated custom tags from prompts
  - Automatic code summarization for custom tags
  - Generate tags from input/output examples

- **Smart Decode**: Automatically detect and decode encoded data
- **Improved Tag Syntax**: Tags now use `</@name>` format for better autocompletion

## Support

- Report issues on [GitHub Issues](https://github.com/hackvertor/hackvertor/issues)
- Visit [Hackvertor GitHub Repository](https://github.com/hackvertor/hackvertor)
- Check the [Tag Store](https://github.com/hackvertor/hackvertor/tree/master/tag-store) for community tags

---

*Hackvertor is developed and maintained by the security research community.*