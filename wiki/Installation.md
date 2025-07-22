# Installation Guide

## Installing from BApp Store (Recommended)

1. Open Burp Suite Professional or Community Edition
2. Navigate to the **Extender** tab
3. Click on the **BApp Store** tab within the Extender tab
4. Scroll down and find **Hackvertor**
5. Click **Install** on the right side

## Manual Installation

If you need to install Hackvertor manually or use a custom build:

1. Download the Hackvertor JAR file from [GitHub Releases](https://github.com/hackvertor/hackvertor/releases)
2. In Burp Suite, go to **Extender** → **Extensions**
3. Click **Add**
4. Select the downloaded JAR file
5. Click **Next** to complete installation

## Verifying Installation

After installation, you should see:
- A new **Hackvertor** tab in the main Burp Suite window
- **Hackvertor** options in right-click context menus throughout Burp
- A **Hackvertor** tab in HTTP message editors

## System Requirements

- Burp Suite Professional or Community Edition
- Java 8 or higher
- Sufficient memory for processing large payloads

## Troubleshooting

### Extension Not Loading
- Ensure you have the correct Java version
- Check Burp Suite's Extender → Errors tab for any error messages
- Try restarting Burp Suite

### Performance Issues
- Allocate more memory to Burp Suite using `-Xmx` flag
- Reduce the complexity of nested tags
- Process smaller chunks of data

### Missing Features
- Ensure you have the latest version of Hackvertor
- Some features may require Burp Suite Professional

## Next Steps

Once installed, proceed to [Getting Started](Getting-Started) to learn how to use Hackvertor.

---

[Back to Home](Home) | [Next: Getting Started](Getting-Started)