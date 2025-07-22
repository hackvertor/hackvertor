# Tag Reference

This page contains all built-in Hackvertor tags organized by category. Examples are taken from actual test cases in the codebase.

## Encode Tags

### Base Encoding

| Tag | Description | Example | Output |
|-----|-------------|---------|--------|
| `base64` | Base64 encode | `<@base64>test</@base64>` | `dGVzdA==` |
| `base64url` | URL-safe Base64 | `<@base64url>Hello World!</@base64url>` | `SGVsbG8gV29ybGQh` |
| `base32` | Base32 encode | `<@base32>test</@base32>` | `ORSXG5A=` |
| `base58` | Base58 encode | `<@base58>test</@base58>` | `3yZe7d` |

### Hex Encoding

| Tag | Description | Example | Output |
|-----|-------------|---------|--------|
| `hex` | Hex encode | `<@hex>ABC</@hex>` | `414243` |
| `hex('separator')` | Hex with separator | `<@hex(' ')>ABC</@hex>` | `41 42 43` |
| `ascii2hex` | ASCII to hex | `<@ascii2hex>ABC</@ascii2hex>` | `414243` |
| `ascii2hex(' ')` | ASCII to hex with separator | `<@ascii2hex(' ')>ABC</@ascii2hex>` | `41 42 43` |

### HTML/XML Encoding

| Tag | Description | Example | Output |
|-----|-------------|---------|--------|
| `html_entities` | HTML entities | `<@html_entities><test></@html_entities>` | `&lt;test&gt;` |
| `hex_entities` | Hex HTML entities | `<@hex_entities>ABC</@hex_entities>` | `&#x41;&#x42;&#x43;` |
| `dec_entities` | Decimal HTML entities | `<@dec_entities>ABC</@dec_entities>` | `&#65;&#66;&#67;` |

### URL Encoding

| Tag | Description | Example | Output |
|-----|-------------|---------|--------|
| `urlencode` | URL encode (space as +) | `<@urlencode>Hello World!</@urlencode>` | `Hello+World%21` |
| `urlencode_all` | URL encode all | `<@urlencode_all>ABC</@urlencode_all>` | `%41%42%43` |

### Other Encoding

| Tag | Description | Example | Output |
|-----|-------------|---------|--------|
| `js_string` | JavaScript string escape | `<@js_string>alert('xss')</@js_string>` | `alert('xss')` |

## Decode Tags

All decode tags start with `d_`:

| Tag | Description | Example | Output |
|-----|-------------|---------|--------|
| `d_base64` | Base64 decode | `<@d_base64>dGVzdA==</@d_base64>` | `test` |
| `d_base64url` | URL-safe Base64 decode | `<@d_base64url>SGVsbG8gV29ybGQh</@d_base64url>` | `Hello World!` |
| `d_base32` | Base32 decode | `<@d_base32>ORSXG5A=</@d_base32>` | `test` |
| `d_base58` | Base58 decode | `<@d_base58>3yZe7d</@d_base58>` | `test` |
| `d_hex` | Hex decode | `<@d_hex>414243</@d_hex>` | `ABC` |
| `d_url` | URL decode | `<@d_url>Hello+World%21</@d_url>` | `Hello World!` |
| `d_html_entities` | HTML entity decode | `<@d_html_entities>&lt;test&gt;</@d_html_entities>` | `<test>` |
| `hex2ascii` | Hex to ASCII | `<@hex2ascii>414243</@hex2ascii>` | `ABC` |

## Hash Tags

| Tag | Description | Example | Output |
|-----|-------------|---------|--------|
| `md5` | MD5 hash | `<@md5>test</@md5>` | `098f6bcd4621d373cade4e832627b4f6` |
| `sha1` | SHA-1 hash | `<@sha1>test</@sha1>` | `a94a8fe5ccb19ba61c4c0873d391e987982fbbd3` |
| `sha256` | SHA-256 hash | `<@sha256>test</@sha256>` | `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` |
| `sha512` | SHA-512 hash | `<@sha512>test</@sha512>` | `ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff` |

## String Manipulation Tags

### Case Conversion

| Tag | Description | Example | Output |
|-----|-------------|---------|--------|
| `uppercase` | Convert to uppercase | `<@uppercase>hello world</@uppercase>` | `HELLO WORLD` |
| `lowercase` | Convert to lowercase | `<@lowercase>HELLO WORLD</@lowercase>` | `hello world` |
| `capitalise` | Capitalize first letter | `<@capitalise>hello world</@capitalise>` | `Hello world` |

### String Operations

| Tag | Description | Example | Output |
|-----|-------------|---------|--------|
| `reverse` | Reverse string | `<@reverse>Hello</@reverse>` | `olleH` |
| `length` | String length | `<@length>Hello World</@length>` | `11` |
| `substring(start,end)` | Extract substring | `<@substring(0,5)>Hello World</@substring>` | `Hello` |
| `replace('old','new')` | Replace text | `<@replace('World','Universe')>Hello World</@replace>` | `Hello Universe` |
| `repeat(count)` | Repeat string | `<@repeat(3)>A</@repeat>` | `AAA` |

## Convert Tags

### Number Base Conversion

| Tag | Description | Example | Output |
|-----|-------------|---------|--------|
| `dec2hex('regex')` | Decimal to hex | `<@dec2hex('(\\d+)')>255</@dec2hex>` | `ff` |
| `hex2dec('regex')` | Hex to decimal | `<@hex2dec('((?:0x)?[a-f0-9]+)')>ff</@hex2dec>` | `255` |
| `dec2bin('regex')` | Decimal to binary | `<@dec2bin('(\\d+)')>10</@dec2bin>` | `1010` |
| `bin2dec('regex')` | Binary to decimal | `<@bin2dec('([0-1]+)')>1010</@bin2dec>` | `10` |

## Encryption/Cipher Tags

| Tag | Description | Example | Note |
|-----|-------------|---------|------|
| `xor('key')` | XOR encryption | `<@xor('key')>Hello</@xor>` | Reversible operation |
| `rotN(13)` | ROT cipher | `<@rotN(13)>Hello</@rotN>` | `Uryyb` |
| `atbash_encrypt` | Atbash cipher | `<@atbash_encrypt>test</@atbash_encrypt>` | Simple substitution |
| `atbash_decrypt` | Atbash decrypt | `<@atbash_decrypt>gvhg</@atbash_decrypt>` | `test` |

## Compression Tags

| Tag | Description | Example | Note |
|-----|-------------|---------|------|
| `gzip_compress` | GZIP compression | `<@gzip_compress>data</@gzip_compress>` | Binary output |
| `gzip_decompress` | GZIP decompression | `<@gzip_decompress>compressed_data</@gzip_decompress>` | Requires GZIP input |

## Special Tags

### Variables

| Tag | Description | Example |
|-----|-------------|---------|
| `set_variable1(bool)` | Set variable | `<@set_variable1(true)>content</@set_variable1>` |
| `get_variable1` | Get variable | `<@get_variable1/>` |

### Math/Utility

| Tag | Description | Example | Output |
|-----|-------------|---------|--------|
| `range(start,end,step)` | Generate range | `<@range(1,5,1)></@range>` | `1,2,3,4,5` |
| `arithmetic(val,op,sep)` | Math operations | `<@arithmetic(5,'+2',',')>1,2,3</@arithmetic>` | `3,4,5` |
| `zeropad(sep,len)` | Zero padding | `<@zeropad(',',3)>1,22,333</@zeropad>` | `001,022,333` |

## Using Tags with Arguments

### String Arguments
Use single or double quotes:
```
<@replace('old','new')>old text</@replace>
<@find("\\w+")>test123</@find>
```

### Numeric Arguments
No quotes needed:
```
<@repeat(5)>X</@repeat>
<@substring(0,10)>Long text here</@substring>
<@rotN(13)>Secret</@rotN>
```

### Boolean Arguments
```
<@set_variable1(true)>value</@set_variable1>
<@set_variable1(false)>value</@set_variable1>
```

### Multiple Arguments
Separate with commas:
```
<@substring(5,10)>Hello World</@substring>
<@range(1,10,2)></@range>
```

## Tag Nesting

Tags can be nested and are processed from innermost to outermost:

```
<@hex><@md5><@uppercase>test</@uppercase></@md5></@hex>
```

Processing order:
1. `uppercase`: test → TEST
2. `md5`: TEST → 033bd94b1168d7e4f0d644c3c95e35bf
3. `hex`: 033bd94b1168d7e4f0d644c3c95e35bf → (hex encoded)

---

[Back to Home](Home) | [Next: Advanced Usage](Advanced-Usage)