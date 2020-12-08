import burp.BurpExtender;
import burp.Convertors;
import burp.Hackvertor;
import burp.parser.Element;
import burp.parser.HackvertorParser;
import burp.parser.ParseException;
import org.json.JSONArray;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Scanner;

public class TestExtension {

    public static void main(String[] args) {
        JFrame jFrame = new JFrame("Burp Suite - Hackvertor");
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jFrame.setContentPane(new JPanel(new BorderLayout()));
        jFrame.setMinimumSize(new Dimension(100,100));
        JMenuBar menuBar = new JMenuBar();
        jFrame.setJMenuBar(menuBar);
        BurpExtender burpExtender = new BurpExtender();
        burpExtender.registerExtenderCallbacks(new StubCallbacks(jFrame));
        jFrame.pack();
        jFrame.setVisible(true);
    }
}
