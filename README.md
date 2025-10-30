![](https://github.com/hackvertor/hackvertor/blob/master/src/main/resources/images/logo-light.png)

# Hackvertor

Hackvertor is a tag based conversion tool written in Java implemented as a Burp Suite extension. Tags are constructed as follows:
`<@base64></@base64>` the @ symbol is used as an identifier that it's a Hackvertor tag followed by the name of the tag in this case base64.

Tags also support arguments. The find tag allows you to find a string by regex and has parenthesis after the tag name:
`<@find("\\w")>abc</@find>` this indicates it supports arguments. The argument in this case is the regex string to find on the text in-between the tags. Hackvertor allows you to use three types of arguments either strings (double, single), boolean (true, false) or numbers (including hex).

# Changelog

## Version v2.2.3 (2025-10-30)

- Large refactor
- Removed reflection in fake tags
- Added helper methods for tag creation
- Created registry instead of large switch statement

## Version v2.1.28 (2025-10-29)

- Added insert last tag context menu item

## Version v2.1.27 (2025-10-23)

- Added multiple new hotkeys
- Fixed tag store display of description and code.

## Version v2.1.23 (2025-09-18)

- Allowed AI in Tag Automator

## Version v2.1.20 (2025-09-18)

- Added examples rules for Tag Automator
- Fixed bugs when creating a rule
- Added warning messages about usage

## Version v2.1.11 (2025-09-17)

- Allow rules to be applied to different tools

## Version v2.1.11 (2025-09-17)

- Renamed profiles to tag automator
- Added clear tags option in Repeater request
- Fixed null pointer in get tag context
- URL decoded data when using it with learn from Repeater

## Version v2.1.7 (2025-09-12)

- Added profiles

## Version v2.1.0 (2025-09-07)

- Changed from old Burp API to montoya.
- Added HttpHandler
- New Context menu
- Fixed bug in settings when declaring ints
- Added max body length setting
- Checked if over max body length and only converted headers.

## Version v2.0.31 (2025-09-05)

- Increased custom param length limit
- Removed issuer validation from JWT verify tag
- Added find and replace option to input/output

## Version v2.0.29 (2025-09-04)

- Added tag execution key to each context tag to prevent misuse by an attacker. 
- Added new context_request tag to capture the full request. 
- Fixed context_url tag with null checks.

## Version v2.0.26 (2025-09-02)

- Fixed UTF-7 encoding/decoding
- Added timeout to system command

## Version v2.0.24 (2025-08-29)

- Added read_file tag

## Version v2.0.23 (2025-08-29)

- Allowed blank JWT secret

## Version v2.0.20 (2025-08-27)

- Added Python module path settings
- Removed requirement of needing test input and output for generating tags with AI.

## Version v2.0.18 (2025-07-22)

- Fixed global variables bug where when deleting a variable it would be retained when restarting Hackvertor. Added hotkey support to invoke smart decode in repeater.
- Showed a different context menu when tags in the proxy are disabled, warning you that tags won't work here.
- Added register hot key check
- Fixed UX bug when editing text and selecting drop down.
- Added hasHotKey flag
- Fixed bug editing tags
- Added read a URL through Burp.
- Made global variables window resizeable and longer.
- Fix: jwt tag
- Added JSON tags
- Added JSON_string_escape tag
- Added zlib compress tag
- Updated submissions rules to remove maximum length limit

## Version 2.0.12 (2025-02-13)

### AI Features
- **Learn from Repeater**: Hackvertor attempts to learn encoding patterns from Repeater requests and generates Python custom tags automatically
- **Summarize Custom Code Tags**: When a custom tag is created, Hackvertor uses AI to summarize what it does
- **AI Custom Tags**: You can now use prompts in custom tags
- **AI Code Generation**: Hackvertor generates custom tags from input/output examples and instructions

## Version 2.0.0 (2025-01-08)

### Improvements
- Added tag execution key rehydrate button
- Made HTTP request editor more compact
- Added smart decode feature
- Changed tag syntax from `<@/name>` to `</@name>` for better autocompletion support

## Version 1.8.10 (2024-01-08)

### New Features
- Added new line and space tags
- Added ean13 tag to the tag store
- Allowed regex replace to use capture groups

## Version 1.8.9 (2023-12-22)

### Bug Fixes
- Fixed #79: No contextual menu entries for requests in Proxy History and Sitemap

## Version 1.8.8 (2023-12-20)

### New Features
- Added remove output tag
- Added load from JSON file
- Added save to JSON file

## Version 1.8.6 (2023-12-20)

### Improvements
- Added line numbers to custom tag editor

## Version 1.8.6 (2023-12-19)

### Major Feature
- Added full support for JavaScript in custom tags

## Version 1.8.5 (2023-12-18)

### Bug Fixes
- Fixed bug where hex default value for custom tag would be quoted

## Version 1.8.4 (2023-11-01)

### Improvements
- Continued improvements on create tag window

## Version 1.8.3 (2023-11-01)

### Improvements
- Disabled install button when tag is installed
- Started work on create new tag to make more room

## Version 1.8.2 (2023-10-31)

### Improvements
- Fixed editing tags without producing duplicates
- Added export to tag store

## Version 1.8.1 (2023-10-30)

### Bug Fixes
- Fixed bug when installing a tag from the tag store with the same name

## Version 1.8 (2023-10-26)

### Major Feature
- Implemented Tag Store: Installable tags from GitHub

# Installation

- In order to use Hackvertor you need to open Burp Suite.
- Click the Extender tab
- Click the BApp store tab inside the Extender tab
- Scroll down and click Hackvertor
- Then click install on the right

# How to use Hackvertor

To use Hackvertor once it has been installed, click on the Hackvertor tab in the main Burp Suite window. You can then type into the input box to create some text to convert. For instance if you want to convert some text to base64, select the text in the input box then click on the encode tab in Hackvertor, then find the base64 tag and click it. Hackvertor will then add the tag around the selected text and the output window will show a base64 encoded string of your text. It's worth noting that Hackvertor supports an unlimited amount of nesting, you can use multiple tags to encode or decode text. Hackvertor will work from the inner most tag to the outer tag and each step will be converted using the relevant tag you have chosen.

# Advanced usage

For more advanced users, you can use tags within repeater tabs. Simply click the repeater tab, right click and select the Hackvertor menu. Then you can use any tag within the repeater tab. Tags will be displayed in the repeater window but when a request is sent they will be converted by Hackvertor and the server will see the converted request. Hackvertor also have a message editor tab, you can select this tab from any request tab in Burp. This will then create the Hackvertor interface inside a request tab, allowing to use the Hackvertor interface to modify a request. 

# Creating custom tags

1. Go to Hackvertor menubar
2. Click "Create custom tag"

# Editing custom tags

1. Go to Hackvertor menubar
2. Click "List custom tags"
3. Select tag to edit
4. Click "Edit tag"

# Deleting custom tag

1. Go to Hackvertor menubar
2. Click "List custom tags"
3. Select tag to delete
4. Click "Delete tag"

# Global variables

Global variables can be used throughout Hackvertor.

## Create a global variable

1. Go to Hackvertor menubar
2. Click "Global variables"
3. Enter variable name and value
4. Click "Create/Update variable"
5. 

## Edit a global variable

1. Go to Hackvertor menubar
2. Click "Global variables"
3. Select variable
4. Click Edit
5. Update variable
6. Click "Create/Update variable"