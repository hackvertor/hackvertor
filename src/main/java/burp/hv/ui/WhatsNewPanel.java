package burp.hv.ui;

import burp.hv.HackvertorExtension;
import burp.hv.utils.Utils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.HyperlinkEvent;
import java.awt.*;
import java.util.List;

/**
 * The "What's new" tab, advertising the features added in recent releases. Rendered as HTML so
 * the content is one readable block of text rather than a pile of Swing components.
 */
public class WhatsNewPanel extends JPanel {

    public static final String TITLE = "What's new";

    private static final String DOCS_URL = "https://github.com/hackvertor/hackvertor/wiki";

    private record Feature(String title, String version, String body) {
    }

    private static final List<Feature> FEATURES = List.of(
            new Feature("Jigsaw mode", "v2.2.61",
                    "Build conversions by dragging tag pieces together instead of typing tags by hand. "
                            + "Switch between <em>Jigsaw mode</em> and <em>Tag mode</em> with the dropdown above the input, "
                            + "and edit a tag's arguments directly on its piece. Your choice of mode is remembered."),
            new Feature("Check tags and tag expressions", "v2.2.65",
                    "The new <code>check</code> tag runs any built in or custom tag against its input and returns "
                            + "true or false, so you can make a conversion conditional:"
                            + "<pre>&lt;@check('isJson','&lt;key&gt;')&gt;{}&lt;/@check&gt; &amp;&amp; &lt;@base64&gt;foo&lt;/@base64&gt;</pre>"
                            + "Combine checks with <code>&amp;&amp;</code> and <code>||</code>, negate them with <code>!</code>, "
                            + "and rely on short circuiting so a tag that cannot change the outcome never runs. Each line is "
                            + "its own expression. Two predicates ship with it, <code>isJson</code> and <code>isNumeric</code>. "
                            + "Expressions only activate when a <code>check</code> tag is present, so existing payloads "
                            + "containing <code>&amp;&amp;</code> are untouched."),
            new Feature("Customisable hotkeys", "v2.2.65",
                    "Pick the modifier used by the Hackvertor hotkeys under "
                            + "<em>Hackvertor &rarr; Settings &rarr; Hotkeys</em>, in case the defaults clash with "
                            + "something else you use. Reload the extension to apply."),
            new Feature("Smart paste", "v2.2.57",
                    "Paste encoded data and Hackvertor works out the encoding and decodes it for you, both in this "
                            + "tab and in Repeater."),
            new Feature("Smarter smart decode", "v2.2.54",
                    "Base64 detection is much better, including base64 split across several lines, which is what you "
                            + "normally get in SMTP and email bodies.")
    );

    public WhatsNewPanel() {
        super(new BorderLayout());
        JEditorPane content = new JEditorPane("text/html", buildHtml());
        content.setEditable(false);
        content.setBorder(new EmptyBorder(15, 20, 20, 20));
        content.setBackground(colourOr(UIManager.getColor("Panel.background"), Color.WHITE));
        content.addHyperlinkListener(event -> {
            if (event.getEventType() == HyperlinkEvent.EventType.ACTIVATED && event.getURL() != null) {
                Utils.openUrl(event.getURL().toString());
            }
        });
        //Start at the top rather than wherever the caret happens to leave it.
        content.setCaretPosition(0);

        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.setBorder(null);
        //Without this the editor pane grows to fit the longest line instead of wrapping.
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);
    }

    private static String buildHtml() {
        Font font = UIManager.getFont("Label.font");
        String family = font == null ? "sans-serif" : font.getFamily();
        int size = font == null ? 12 : font.getSize();

        //Everything is derived from the look and feel rather than from the theme flag, so the code
        //blocks and muted text can never end up the same shade as the text sitting on them.
        Color background = colourOr(UIManager.getColor("Panel.background"), Color.WHITE);
        Color foreground = colourOr(UIManager.getColor("Label.foreground"), Color.BLACK);
        boolean darkBackground = luminance(background) < 0.5;
        String bodyColour = toHex(foreground);
        String mutedColour = toHex(blend(foreground, background, 0.45));
        String codeBackground = toHex(shade(background, darkBackground ? 26 : -18));
        String headingColour = toHex(darkBackground
                ? blend(UIUtils.PRIMARY_COLOR, Color.WHITE, 0.55)
                : UIUtils.PRIMARY_COLOR);

        StringBuilder html = new StringBuilder();
        html.append("<html><head><style>")
                .append("body { font-family:").append(family).append("; font-size:").append(size)
                .append("pt; color:").append(bodyColour).append("; }")
                .append("h1 { font-size:").append(size + 6).append("pt; margin:0 0 2px 0; }")
                .append("h2 { font-size:").append(size + 2).append("pt; color:").append(headingColour)
                .append("; margin:18px 0 4px 0; }")
                .append(".version { color:").append(mutedColour).append("; font-size:").append(size - 1)
                .append("pt; }")
                .append("a { color:").append(headingColour).append("; }")
                .append("code, pre { background:").append(codeBackground)
                .append("; font-family:monospace; }")
                .append("pre { padding:6px; margin:8px 0; }")
                .append("p { margin:4px 0 0 0; }")
                .append("</style></head><body>");

        html.append("<h1>What's new in Hackvertor</h1>")
                .append("<p class=\"version\">You are running ").append(HackvertorExtension.version)
                .append(". Full documentation is on the <a href=\"").append(DOCS_URL).append("\">wiki</a>.</p>");

        for (Feature feature : FEATURES) {
            html.append("<h2>").append(feature.title()).append("</h2>")
                    .append("<p class=\"version\">Added in ").append(feature.version()).append("</p>")
                    .append("<p>").append(feature.body()).append("</p>");
        }

        return html.append("</body></html>").toString();
    }

    private static Color colourOr(Color colour, Color fallback) {
        return colour == null ? fallback : colour;
    }

    private static String toHex(Color colour) {
        return String.format("#%02x%02x%02x", colour.getRed(), colour.getGreen(), colour.getBlue());
    }

    private static double luminance(Color colour) {
        return (0.299 * colour.getRed() + 0.587 * colour.getGreen() + 0.114 * colour.getBlue()) / 255d;
    }

    /** Moves every channel by {@code amount}, so a dark background lightens and a light one darkens. */
    private static Color shade(Color colour, int amount) {
        return new Color(clamp(colour.getRed() + amount), clamp(colour.getGreen() + amount),
                clamp(colour.getBlue() + amount));
    }

    private static Color blend(Color from, Color to, double ratio) {
        return new Color(
                clamp((int) Math.round(from.getRed() + (to.getRed() - from.getRed()) * ratio)),
                clamp((int) Math.round(from.getGreen() + (to.getGreen() - from.getGreen()) * ratio)),
                clamp((int) Math.round(from.getBlue() + (to.getBlue() - from.getBlue()) * ratio)));
    }

    private static int clamp(int value) {
        return Math.max(0, Math.min(255, value));
    }
}
