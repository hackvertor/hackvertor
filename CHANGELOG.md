# Changelog

## Version v2.2.43 (2026-02-18)

- Merge pull request #156 from snooze6/master
- reverted bappmanifest.bmf
- Merge pull request #157 from psalire/master
- Fixed parser bug with self-closing tags and space. Added tests to cover it.
- Center JDialog/JOption relative to parent
- Center new JFrames on the current screen
- fix format, bump version and remove unused id
- fix websockets
- improving hex
- Update CHANGELOG.md for v2.2.42

## Version v2.2.43 (2026-01-21)
- Improved hex UI
- Added support to websockets using Montoya API
- Bumped the version

## Version v2.2.42 (2026-01-21)

- Improved auto decoding
- Fixed dark theme UI issues
- Moved version output and improved button layout
- Fixed problems when in dark mode on EA
- Fixed all tags ui test to look for converted output too
- Fixed UI tests and reverted regex changes to partial autodecode
- Fixed smart decode to be a bit stricter
- Merged smart decode and super decode into one action
- Created super decode feature. Fixed button layout with wrapped layout.
- Removed duplicate header in changelog and fixed github action to prevent duplicates

## Version v2.2.38 (2026-01-06)

- Updated github workflow to allow manual dispatch
- Bumped the version
- Merge remote-tracking branch 'origin/master'
- Added send selection to Hackvertor for responses and requests.
- Update CHANGELOG.md for v2.2.36

## Version v2.2.36 (2026-01-06)

- Fixed autodecoder to detect compressed headers Renamed add and remove layer buttons. Moved layers buttons and made categories spread across
- Updated Github workflow
- Update README.md
- Moved changelog to separate file

## Version v2.2.34 (2025-12-17)

- Fixed smart decoding bug
- Added more tag automator examples.

## Version v2.2.33 (2025-11-27)

- Added category checkboxes and a message when all variants are copied,
- Made the filter using the tag name. Changed dimensions.
- Added filter to output preview
- Added the first layer tag as the name of the Repeater tab
- Prevented dangerous categories from being shown in the MultiEncoderWindow. Added checkboxes to enable them. Made the window persist state in the project file when closed.

## Version v2.2.26 (2025-11-26)

- Fixed dialog problems
- Added limits for multiencoder

## Version v2.2.24 (2025-11-26)

- Fixed deflate, base32 detection
- Improved auto decoder (smart decoding)

## Version v2.2.24 (2025-11-25)

- Updated TagAutomator rules to allow multiple tools per rule
- Added multi encoder window
- Added websockets setting and websocket handler
- Added copy to clipboard button, clear button and select all checkbox to the MultiEncoderWindow.
- Fixed send to intruder
- Added layers to MultiEncoderWindow
- Added MultiEncoderWindow to the HackvertorExtension panel and added sendToHackvertor button
- Fixed the layers to work correctly. The layers now apply the nesting
- Added limits to MultiEncoderWindow

## Version v2.2.16 (2025-11-20)

- Changed HTTP handler to allow interception when there are Tag Automation rules

## Version v2.2.15 (2025-11-15)

- Improved tag finder to be used within Hackvertor Panel
- Applied Burp theme to components

## Version v2.2.13 (2025-11-13)

- Used Montoya compression utils
- Tag finder window

## Version v2.2.12 (2025-11-13)

- Fixed Burp capability checks now Montoya API has been released.

## Version v2.2.10 (2025-11-7)

- Fixed grid layout issues
- Added tooltips

## Version v2.2.6 (2025-11-6)

- Made history local to message editor tab separate from global history.
- Disabled history when output is hidden.

## Version v2.2.5 (2025-11-1)

- Added Hackvertor history
- Remembered tab state
- UI fixes to tab panel
- Added setting to show output in message editor

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