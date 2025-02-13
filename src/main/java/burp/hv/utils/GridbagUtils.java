package burp.hv.utils;

import java.awt.*;

public class GridbagUtils {
    public static GridBagConstraints addMarginToGbc(GridBagConstraints gbc, int top, int left, int bottom, int right) {
        gbc.insets = new Insets(top, left, bottom, right);
        return gbc;
    }

    public static GridBagConstraints createConstraints(int x, int y, int gridWidth, int fill, double weightx, double weighty, int ipadx, int ipady, int anchor) {
        GridBagConstraints c = new GridBagConstraints();
        c.fill = fill;
        c.gridx = x;
        c.gridy = y;
        c.ipadx = ipadx;
        c.ipady = ipady;
        c.gridwidth = gridWidth;
        c.weightx = weightx;
        c.weighty = weighty;
        c.anchor = anchor;
        return c;
    }
}
