package burp.hv.ui;

import burp.hv.Hackvertor;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;
import java.awt.event.ActionEvent;

public class SmartDecodeAction extends AbstractAction  {
    private Hackvertor hackvertor;
    private JTextArea inputArea;
    private JTextArea outputArea;
    public SmartDecodeAction(JTextArea inputArea, RSyntaxTextArea outputArea, Hackvertor hackvertor) {
        this.inputArea = inputArea;
        this.outputArea = outputArea;
        this.hackvertor = hackvertor;
    }

    public void actionPerformed(ActionEvent e) {
        if(inputArea.getSelectionStart() == inputArea.getSelectionEnd()) {
            return;
        }
        if(outputArea == null) {
            inputArea.replaceSelection(hackvertor.convert("<@auto_decode_no_decrypt>" + inputArea.getSelectedText() + "</@auto_decode_no_decrypt>", hackvertor));
        } else {
            outputArea.replaceSelection(hackvertor.convert("<@auto_decode_no_decrypt>" + inputArea.getSelectedText() + "</@auto_decode_no_decrypt>", hackvertor));
        }
    }
}
