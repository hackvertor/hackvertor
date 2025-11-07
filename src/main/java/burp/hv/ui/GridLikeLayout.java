package burp.hv.ui;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public final class GridLikeLayout {

    public static void apply(JPanel target, List<? extends JComponent> components, int rows, int fitIndices) {
        apply(target, components, rows, fitIndices, -1);
    }

    public static void apply(JPanel target, List<? extends JComponent> components, int rows, int fitIndices, int doubleWidthIndex) {
        if (rows < 1 || rows > 2) throw new IllegalArgumentException("rows must be 1 or 2");
        GridBagLayout gbl = (GridBagLayout) target.getLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridy = 0;
        gbc.gridx = 0;

        int n = components.size();
        int cols = (rows == 1) ? n : (int) Math.ceil(n / 2.0);

        int currentCol = 0;
        int currentRow = 0;

        for (int i = 0; i < n; i++) {
            JComponent c = components.get(i);

            gbc.gridx = currentCol;
            gbc.gridy = currentRow;

            if (rows == 2 && i == doubleWidthIndex) {
                gbc.gridwidth = 2;
            } else {
                gbc.gridwidth = 1;
            }

            boolean isFit = ((fitIndices >> i) & 1) == 1;

            if (isFit) {
                gbc.weightx = 0.0;
                gbc.weighty = 0.0;
                gbc.fill = GridBagConstraints.NONE;
                gbc.anchor = GridBagConstraints.WEST;
            } else {
                gbc.weightx = 1.0;
                gbc.weighty = (rows == 1) ? 1.0 : 1.0;
                gbc.fill = GridBagConstraints.BOTH;
                gbc.anchor = GridBagConstraints.CENTER;
            }

            target.add(c, gbc);

            currentCol += gbc.gridwidth;
            if (rows == 2 && currentCol >= cols) {
                currentCol = 0;
                currentRow++;
            }
        }

        boolean allFit = (fitIndices == (1 << components.size()) - 1);
        if (allFit) {
            gbc.gridx = (rows == 1) ? components.size() : 0;
            gbc.gridy = (rows == 1) ? 0 : 2;
            gbc.weightx = 1.0;
            gbc.weighty = 1.0;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.anchor = GridBagConstraints.CENTER;
            target.add(Box.createGlue(), gbc);
        }

        target.revalidate();
    }

    public static JPanel makePanel(List<? extends JComponent> components, int rows, int fitIndices) {
        JPanel p = new JPanel(new GridBagLayout());
        apply(p, components, rows, fitIndices);
        return p;
    }
}