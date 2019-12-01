![](https://github.com/hackvertor/hackvertor/blob/master/src/main/resources/images/logo-light.png)

# Hackvertor

Hackvertor is a tag based conversion tool written in Java implemented as a Burp Suite extension. Tags are constructed as follows:
<@base64_0><@/base64_0> the @ symbol is used as an identifier that it's a Hackvertor tag followed by the name of the tag in this case base64, the name is then followed by an underscore and a unique tag number.

Tags also support arguments. The find tag allows you to find a string by regex and has parenthesis after the unique tag number:
<@find_0("\\w")>abc<@/find_0> this indicates it supports arguments. The argument in this case is the regex string to find on the text inbetween the tags. Hackvertor allows you to use two types of arguments either strings (double, single) or numbers (including hex).

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
