import hackvertor.HackvertorExtension;

import javax.swing.*;
import java.awt.*;

public class TestExtension {

    public static void main(String[] args) {
        JFrame jFrame = new JFrame("Burp Suite - Hackvertor");
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jFrame.setContentPane(new JPanel(new BorderLayout()));
        jFrame.setPreferredSize(new Dimension(900,800));
        JMenuBar menuBar = new JMenuBar();
        jFrame.setJMenuBar(menuBar);
        HackvertorExtension hackvertorExtension = new HackvertorExtension();
        hackvertorExtension.registerExtenderCallbacks(new StubCallbacks(jFrame));
        jFrame.pack();
        jFrame.setVisible(true);
    }
}
