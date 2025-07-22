import burp.hv.HackvertorExtension;
import burp.hv.utils.Utils;
import burp.stubs.StubCallbacks;

import javax.swing.*;
import java.awt.*;

public class TestExtension {

    public static void main(String[] args) {
        JFrame jFrame = new JFrame("Burp Suite - Hackvertor");
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jFrame.setContentPane(new JPanel(new BorderLayout()));
        jFrame.setPreferredSize(new Dimension(1200,1000));
        HackvertorExtension hackvertorExtension = new HackvertorExtension();
        hackvertorExtension.registerExtenderCallbacks(new StubCallbacks(jFrame));
        JMenuBar menuBar = new JMenuBar();
        menuBar.add(Utils.generateHackvertorMenuBar());
        jFrame.setJMenuBar(menuBar);
        jFrame.pack();
        jFrame.setVisible(true);
    }
}
