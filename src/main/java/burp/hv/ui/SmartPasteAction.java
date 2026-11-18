package burp.hv.ui;

import burp.hv.utils.Utils;
import burp.hv.Convertors;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
import java.io.IOException;

public class SmartPasteAction extends AbstractAction {
    private final JTextArea inputArea;

    public SmartPasteAction(JTextArea inputArea) {
        this.inputArea = inputArea;
    }

    public void actionPerformed(ActionEvent e) {
        String clipboard;
        try {
            clipboard = (String) Utils.getClipboard().getData(DataFlavor.stringFlavor);
        } catch (UnsupportedFlavorException | IOException ex) {
            return;
        }
        if (clipboard == null) {
            return;
        }
        inputArea.replaceSelection(Convertors.smartDecode(clipboard));
    }
}
