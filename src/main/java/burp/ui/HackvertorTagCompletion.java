package burp.ui;

import burp.Hackvertor;
import org.fife.ui.autocomplete.AutoCompletion;
import org.fife.ui.autocomplete.Completion;
import org.fife.ui.autocomplete.CompletionProvider;
import org.fife.ui.autocomplete.ParameterizedCompletion;

import javax.swing.text.Caret;
import javax.swing.text.JTextComponent;

public class HackvertorTagCompletion extends AutoCompletion {
    private Hackvertor hackvertor;
    public HackvertorTagCompletion(CompletionProvider provider) {
        super(provider);
    }
    protected void insertCompletion(Completion c,
                                    boolean typedParamListStartChar) {

        JTextComponent textComp = getTextComponent();
        String alreadyEntered = c.getAlreadyEntered(textComp);
        hidePopupWindow();
        Caret caret = textComp.getCaret();

        int dot = caret.getDot();
        int len = alreadyEntered.length();
        int start = dot - len;
        String replacement = getReplacementText(c, textComp.getDocument(),
                start, len);

        caret.setDot(start);
        caret.moveDot(dot);
        String startTag = "@" + replacement + ">";
        String endTag = "<@/" + replacement + ">";
        textComp.replaceSelection(startTag + endTag);
        caret.moveDot(caret.getDot()-endTag.length());
    }
}
