# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Hackvertor is a Java-based Burp Suite extension that provides tag-based data transformation capabilities. It supports various encoding/decoding operations, cryptographic functions, and custom scripting languages. The extension integrates deeply with Burp Suite's UI and provides both standalone and contextual processing of HTTP requests.

## Development Commands

### Build and Test
```bash
# Build the project
./gradlew build

# Run tests
./gradlew test

# Create distribution JAR
./gradlew jar

# Create shadow JAR (includes all dependencies)
./gradlew shadowJar
```

### Development Testing
```bash
# Run standalone test application
./gradlew test --tests TestExtension
```

## Architecture Overview

### Core Components

- **HackvertorExtension**: Main extension entry point implementing both legacy (`IBurpExtender`) and new (`BurpExtension`) Burp APIs
- **Hackvertor**: Core processing engine that manages tags and performs conversions
- **Convertors**: Static utility class containing all conversion logic and tag implementations
- **Tag System**: Hierarchical tag categories (Encode, Decode, Hash, Encrypt, etc.) with argument support
- **Custom Tags**: User-defined tags supporting Python, JavaScript, Java, and Groovy scripting
- **AI Integration**: Recent addition for generating custom tags and learning from requests

### Key Directories

- `src/main/java/burp/hv/`: Core Hackvertor implementation
- `src/main/java/burp/hv/ui/`: UI components and panels
- `src/main/java/burp/hv/tags/`: Tag system implementation
- `src/main/java/burp/hv/ai/`: AI-powered features
- `src/main/java/burp/hv/settings/`: Configuration management
- `src/main/javacc/`: Parser grammar definitions
- `src/test/java/`: Test infrastructure with stub implementations
- `tag-store/`: External tag repository with installable custom tags

### Parser System

The project uses JavaCC for parsing Hackvertor tag syntax. The parser grammar is defined in `src/main/javacc/burp/parser/parser.jj` and generates parsing classes during build.

### Tag Processing Flow

1. Input text is parsed by `HackvertorParser` to identify tags and content
2. Tags are processed recursively from innermost to outermost
3. Each tag lookup in `Convertors` class finds the appropriate conversion method
4. Custom tags are executed via script engines (Python/Jython, JavaScript/GraalVM, Java/BeanShell, Groovy)
5. Results are assembled back into the final output

### Integration Points

- **Burp Suite Tabs**: Main Hackvertor tab with input/output panels
- **Context Menus**: Right-click integration in Proxy, Repeater, etc.
- **Message Editor Tabs**: Hackvertor processing within request/response viewers
- **Intruder Payload Processors**: Each tag available as payload processor
- **Hotkey Support**: Ctrl+Alt+D for auto-decode functionality

## Key Implementation Details

### Security Model
- Custom code execution requires explicit key validation (`tagCodeExecutionKey`)
- Script engines run in controlled contexts with limited access
- File system operations are restricted to specific directories

### Performance Considerations
- Single-threaded executor service for background tasks
- Caching of frequently used conversions
- Efficient parser with minimal memory allocation

### Extension Lifecycle
- Initializes both legacy and Montoya APIs simultaneously
- Loads custom tags and global variables on startup
- Registers all UI components, processors, and listeners
- Proper cleanup on extension unload

## Custom Tag Development

Custom tags support multiple scripting languages:
- **Python**: Uses Jython interpreter
- **JavaScript**: Uses GraalVM polyglot engine
- **Java**: Uses BeanShell interpreter
- **Groovy**: Uses Groovy shell

Each custom tag has access to:
- `input`: The text to process
- `output`: Variable to set the result
- Tag-specific arguments as variables

## Testing

The project includes JUnit tests and stub implementations for Burp Suite APIs. The `TestExtension` class provides a standalone test harness for development.

## Dependencies

Key dependencies include:
- Burp Suite Extender API and Montoya API
- Apache Commons libraries (codec, lang3, compress, io)
- Bouncy Castle cryptography
- GraalVM for JavaScript
- Jython for Python scripting
- Groovy runtime
- JSON processing libraries