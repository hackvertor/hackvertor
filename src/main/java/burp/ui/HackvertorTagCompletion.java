package burp.ui;

import burp.Convertors;
import burp.Hackvertor;
import burp.Tag;
import burp.Utils;
import org.fife.ui.autocomplete.AutoCompletion;
import org.fife.ui.autocomplete.Completion;
import org.fife.ui.autocomplete.CompletionProvider;
import org.fife.ui.autocomplete.ParameterizedCompletion;

import javax.swing.text.Caret;
import javax.swing.text.JTextComponent;
import java.util.ArrayList;
import java.util.Optional;

public class HackvertorTagCompletion extends AutoCompletion {
    private ArrayList<Tag> tags;

    public HackvertorTagCompletion(CompletionProvider provider, ArrayList<Tag> tagsList) {
        super(provider);
        this.tags = tagsList;
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
        String tagName = getReplacementText(c, textComp.getDocument(), start, len);

        caret.setDot(start);
        caret.moveDot(dot);
        Optional<Tag> tagObj = tags.stream().filter(o -> o.name.equals(tagName)).findFirst();
        if(tagObj.isPresent()) {
            String[] tag = Convertors.generateTagStartEnd(tagObj.get());
            String startTag = tag[0].substring(1);
            String endTag = tag[1];
            textComp.replaceSelection(startTag + endTag);
            int pos = caret.getDot() - endTag.length();
            caret.moveDot(pos);
            textComp.select(pos, pos);
        }
    }
}
