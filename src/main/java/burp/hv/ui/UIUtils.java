package burp.hv.ui;

import burp.hv.HackvertorExtension;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class UIUtils {

    public static final Color PRIMARY_COLOR = new Color(15, 91, 114);
    public static final Color PRIMARY_TEXT_COLOR = Color.WHITE;

    public static void applyHackvertorInputStyle(HackvertorInput input) {
        applyTextAreaBorderStyle(input);
    }

    public static void applyTextAreaBorderStyle(JTextArea area) {
        Color colour = HackvertorExtension.isDarkTheme ? Color.decode("#2b2b2b") :  Color.decode("#dfdfdf");
        area.setBorder(BorderFactory.createLineBorder(colour));
    }

    public static void applyPrimaryStyle(JButton button) {
        button.setBackground(PRIMARY_COLOR);
        button.setForeground(PRIMARY_TEXT_COLOR);
    }

    public static void applyLengthStyle(JLabel label) {
        label.setBackground(Color.decode("#e2b53f"));
        label.setForeground(Color.black);
        label.setBorder(new EmptyBorder(5, 5, 5, 5));
    }

    public static void applyUnicodeLengthStyle(JLabel label) {
        label.setBackground(Color.decode("#fe6767"));
        label.setForeground(Color.black);
        label.setBorder(new EmptyBorder(5, 5, 5, 5));
    }
}
