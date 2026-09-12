package burp.hv.ui.jigsaw;

import burp.hv.Hackvertor;
import burp.hv.tags.Tag;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Consumer;

public class JigsawBoard extends JPanel {

    private static final int MARGIN = 16;
    private static final int ROW_GAP = 14;
    private static final int ROW_HEIGHT = 52;
    private static final int SNAP_DISTANCE = 36;
    private static final int GRID_SPACING = 20;
    private static final String HINT = "Click a tag or +Text to add a piece, then drag pieces together";
    private static final String REMOVAL_HINT = "Release to remove";

    private final Hackvertor hackvertor;
    private JigsawPiece selected;
    private JigsawPiece dragged;
    private boolean removalPending;
    private Rectangle snapGhost;
    private Consumer<String> changeListener;
    private boolean loading;

    public JigsawBoard(Hackvertor hackvertor) {
        this.hackvertor = hackvertor;
        setLayout(null);
        setFocusable(true);
        setBackground(JigsawColours.board());
        addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent event) {
                requestFocusInWindow();
                if (event.isPopupTrigger()) {
                    showBoardMenu(event);
                    return;
                }
                clearSelection();
            }

            @Override
            public void mouseReleased(MouseEvent event) {
                if (event.isPopupTrigger()) {
                    showBoardMenu(event);
                }
            }
        });
        getInputMap().put(KeyStroke.getKeyStroke("DELETE"), "deleteSelectedPiece");
        getInputMap().put(KeyStroke.getKeyStroke("BACK_SPACE"), "deleteSelectedPiece");
        getActionMap().put("deleteSelectedPiece", new AbstractAction() {
            public void actionPerformed(ActionEvent event) {
                if (selected != null) {
                    deletePiece(selected);
                }
            }
        });
    }

    public void setChangeListener(Consumer<String> changeListener) {
        this.changeListener = changeListener;
    }

    public List<JigsawPiece> pieces() {
        List<JigsawPiece> pieces = new ArrayList<>();
        for (Component component : getComponents()) {
            if (component instanceof JigsawPiece) {
                pieces.add((JigsawPiece) component);
            }
        }
        return pieces;
    }

    private List<JigsawPiece> sortedRoots() {
        List<JigsawPiece> roots = new ArrayList<>();
        for (JigsawPiece piece : pieces()) {
            if (piece.getPrevious() == null) {
                roots.add(piece);
            }
        }
        roots.sort(Comparator.comparingInt((JigsawPiece piece) -> piece.getY() / ROW_HEIGHT)
                .thenComparingInt(Component::getX));
        return roots;
    }

    public String serialize() {
        StringBuilder builder = new StringBuilder();
        for (JigsawPiece root : sortedRoots()) {
            String accumulated = "";
            for (JigsawPiece piece = root; piece != null; piece = piece.getNext()) {
                accumulated = piece.wrap(accumulated);
            }
            builder.append(accumulated);
        }
        return builder.toString();
    }

    public void loadFromText(String text) {
        loading = true;
        removeAll();
        selected = null;
        snapGhost = null;
        List<List<JigsawPiece>> chains = new JigsawTextParser(this, hackvertor.getTags()).chainsFor(text);
        int y = MARGIN;
        for (List<JigsawPiece> chain : chains) {
            JigsawPiece previous = null;
            int height = 0;
            for (JigsawPiece piece : chain) {
                add(piece);
                piece.setSize(piece.getPreferredSize());
                height = Math.max(height, piece.getHeight());
                if (previous != null) {
                    previous.setNext(piece);
                }
                previous = piece;
            }
            if (!chain.isEmpty()) {
                chain.get(0).setLocation(MARGIN, y);
                layoutChain(chain.get(0));
            }
            y += height + ROW_GAP;
        }
        loading = false;
        revalidate();
        repaint();
    }

    public void addTagPiece(Tag tag) {
        insertPiece(new JigsawTagPiece(this, tag, null));
    }

    public void addTextPiece(String text) {
        JigsawTextPiece piece = new JigsawTextPiece(this, text);
        insertPiece(piece);
        piece.focusEditor();
    }

    public void clear() {
        removeAll();
        selected = null;
        snapGhost = null;
        boardChanged();
    }

    private void insertPiece(JigsawPiece piece) {
        JigsawPiece attachTo = selected != null ? selected : lastChainTail();
        add(piece);
        piece.setSize(piece.getPreferredSize());
        if (attachTo != null) {
            JigsawPiece following = attachTo.getNext();
            attachTo.setNext(piece);
            if (following != null) {
                piece.setNext(following);
            }
            layoutChain(piece.root());
        } else {
            piece.setLocation(MARGIN, nextFreeRow());
        }
        selectPiece(piece);
        bringToFront(List.of(piece));
        boardChanged();
    }

    private JigsawPiece lastChainTail() {
        List<JigsawPiece> roots = sortedRoots();
        return roots.isEmpty() ? null : roots.get(roots.size() - 1).tail();
    }

    private int nextFreeRow() {
        int bottom = 0;
        for (JigsawPiece piece : pieces()) {
            bottom = Math.max(bottom, piece.getY() + piece.getHeight());
        }
        return bottom == 0 ? MARGIN : bottom + ROW_GAP;
    }

    public void layoutChain(JigsawPiece root) {
        int x = root.getX();
        int y = root.getY();
        for (JigsawPiece piece = root; piece != null; piece = piece.getNext()) {
            piece.setSize(piece.getPreferredSize());
            piece.setLocation(x, y);
            x += piece.bodyWidth();
        }
    }

    public void selectPiece(JigsawPiece piece) {
        if (selected != null && selected != piece) {
            selected.setSelected(false);
        }
        selected = piece;
        piece.setSelected(true);
    }

    public void clearSelection() {
        if (selected != null) {
            selected.setSelected(false);
            selected = null;
        }
    }

    public void bringToFront(List<JigsawPiece> pieces) {
        for (JigsawPiece piece : pieces) {
            setComponentZOrder(piece, 0);
        }
    }

    public void pieceEdited(JigsawPiece piece) {
        piece.refreshSize();
        layoutChain(piece.root());
        boardChanged();
    }

    public void deletePiece(JigsawPiece piece) {
        JigsawPiece previous = piece.getPrevious();
        JigsawPiece next = piece.getNext();
        Point position = piece.getLocation();
        piece.unlink();
        remove(piece);
        if (previous != null && next != null) {
            previous.setNext(next);
        }
        if (previous != null) {
            layoutChain(previous.root());
        } else if (next != null) {
            next.setLocation(position);
            layoutChain(next);
        }
        if (selected == piece) {
            selected = previous != null ? previous : next;
            if (selected != null) {
                selected.setSelected(true);
            }
        }
        boardChanged();
    }

    public void deleteChain(JigsawPiece piece) {
        for (JigsawPiece member : piece.root().chainFromHere()) {
            if (selected == member) {
                selected = null;
            }
            member.unlink();
            remove(member);
        }
        boardChanged();
    }

    public void showPieceMenu(JigsawPiece piece, MouseEvent event) {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem deletePiece = new JMenuItem("Delete piece");
        deletePiece.addActionListener(action -> deletePiece(piece));
        JMenuItem deleteChain = new JMenuItem("Delete whole chain");
        deleteChain.addActionListener(action -> deleteChain(piece));
        JMenuItem detach = new JMenuItem("Detach from previous piece");
        detach.setEnabled(piece.getPrevious() != null);
        detach.addActionListener(action -> {
            piece.detachFromPrevious();
            piece.setLocation(piece.getX(), piece.getY() + piece.getHeight() + ROW_GAP);
            layoutChain(piece);
            boardChanged();
        });
        menu.add(deletePiece);
        menu.add(deleteChain);
        menu.add(detach);
        Point position = SwingUtilities.convertPoint(event.getComponent(), event.getPoint(), this);
        menu.show(this, position.x, position.y);
    }

    private void showBoardMenu(MouseEvent event) {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem addText = new JMenuItem("Add text piece");
        addText.addActionListener(action -> addTextPiece(""));
        JMenuItem clearBoard = new JMenuItem("Clear board");
        clearBoard.addActionListener(action -> clear());
        menu.add(addText);
        menu.add(clearBoard);
        menu.show(this, event.getX(), event.getY());
    }

    public void previewDrag(JigsawPiece piece, Point pointer) {
        dragged = piece;
        removalPending = isOutsideInput(pointer);
        if (removalPending) {
            snapGhost = null;
            repaint();
            return;
        }
        SnapTarget target = findSnapTarget(piece);
        snapGhost = target == null ? null : ghostFor(piece, target);
        repaint();
    }

    public void dropPiece(JigsawPiece piece, Point pointer) {
        boolean removeDraggedPieces = isOutsideInput(pointer);
        dragged = null;
        removalPending = false;
        snapGhost = null;
        if (removeDraggedPieces) {
            deleteChain(piece);
            return;
        }
        SnapTarget target = findSnapTarget(piece);
        if (target != null) {
            if (target.afterTarget) {
                target.piece.setNext(piece);
                layoutChain(target.piece.root());
            } else {
                piece.tail().setNext(target.piece);
                layoutChain(piece.root());
            }
        }
        boardChanged();
    }

    private Rectangle ghostFor(JigsawPiece piece, SnapTarget target) {
        if (target.afterTarget) {
            return new Rectangle(target.piece.getX() + target.piece.bodyWidth(), target.piece.getY(),
                    piece.getWidth(), piece.getHeight());
        }
        Point tailConnector = piece.tail().outConnector();
        Point socket = target.piece.inConnector();
        return new Rectangle(piece.getX() + socket.x - tailConnector.x,
                piece.getY() + socket.y - tailConnector.y, piece.getWidth(), piece.getHeight());
    }

    public Rectangle dragLimits() {
        Rectangle visible = getVisibleRect();
        return visible.isEmpty() ? new Rectangle(0, 0, Math.max(getWidth(), 1), Math.max(getHeight(), 1)) : visible;
    }

    private boolean isOutsideInput(Point pointer) {
        Rectangle visible = getVisibleRect();
        return !visible.isEmpty() && !visible.contains(pointer);
    }

    private Rectangle chainBounds(JigsawPiece piece) {
        Rectangle bounds = null;
        for (JigsawPiece member : piece.chainFromHere()) {
            bounds = bounds == null ? member.getBounds() : bounds.union(member.getBounds());
        }
        return bounds;
    }

    private SnapTarget findSnapTarget(JigsawPiece piece) {
        List<JigsawPiece> group = piece.chainFromHere();
        JigsawPiece tail = piece.tail();
        SnapTarget best = null;
        for (JigsawPiece candidatePiece : pieces()) {
            if (group.contains(candidatePiece)) {
                continue;
            }
            if (candidatePiece.getNext() == null) {
                best = closer(best, candidate(candidatePiece, true, candidatePiece.outConnector(), piece.inConnector()));
            }
            if (candidatePiece.getPrevious() == null) {
                best = closer(best, candidate(candidatePiece, false, tail.outConnector(), candidatePiece.inConnector()));
            }
        }
        return best;
    }

    private SnapTarget candidate(JigsawPiece piece, boolean afterTarget, Point from, Point to) {
        double distance = from.distance(to);
        if (distance > SNAP_DISTANCE) {
            return null;
        }
        SnapTarget target = new SnapTarget();
        target.piece = piece;
        target.afterTarget = afterTarget;
        target.distance = distance;
        return target;
    }

    private SnapTarget closer(SnapTarget current, SnapTarget candidate) {
        if (candidate == null) {
            return current;
        }
        return current == null || candidate.distance < current.distance ? candidate : current;
    }

    private void boardChanged() {
        revalidate();
        repaint();
        if (changeListener != null && !loading) {
            changeListener.accept(serialize());
        }
    }

    @Override
    public Dimension getPreferredSize() {
        int width = 0;
        int height = 0;
        for (JigsawPiece piece : pieces()) {
            width = Math.max(width, piece.getX() + piece.getWidth());
            height = Math.max(height, piece.getY() + piece.getHeight());
        }
        return new Dimension(width + MARGIN, Math.max(height + MARGIN, ROW_HEIGHT * 3));
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        g.setColor(JigsawColours.board());
        g.fillRect(0, 0, getWidth(), getHeight());
        g.setColor(JigsawColours.grid());
        for (int x = GRID_SPACING; x < getWidth(); x += GRID_SPACING) {
            for (int y = GRID_SPACING; y < getHeight(); y += GRID_SPACING) {
                g.fillRect(x, y, 1, 1);
            }
        }
        if (pieces().isEmpty()) {
            g.setColor(JigsawColours.hint());
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            FontMetrics metrics = g.getFontMetrics();
            g.drawString(HINT, MARGIN, MARGIN + metrics.getAscent());
        }
        g.dispose();
    }

    @Override
    protected void paintChildren(Graphics graphics) {
        super.paintChildren(graphics);
        Graphics2D g = (Graphics2D) graphics.create();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setStroke(new BasicStroke(2.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 1f, new float[]{6f, 5f}, 0f));
        if (snapGhost != null) {
            g.setColor(JigsawColours.SELECTION);
            g.drawRoundRect(snapGhost.x, snapGhost.y, snapGhost.width - JigsawPiece.KNOB_RADIUS, snapGhost.height, 12, 12);
        }
        if (removalPending && dragged != null) {
            Rectangle bounds = chainBounds(dragged);
            g.setColor(JigsawColours.REMOVAL);
            g.drawRoundRect(bounds.x - 3, bounds.y - 3, bounds.width + 6, bounds.height + 6, 14, 14);
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            Rectangle visible = getVisibleRect();
            FontMetrics metrics = g.getFontMetrics();
            int labelY = Math.max(bounds.y - 8, visible.y + metrics.getAscent());
            int labelX = Math.max(visible.x + 2,
                    Math.min(bounds.x, visible.x + visible.width - metrics.stringWidth(REMOVAL_HINT) - 2));
            g.drawString(REMOVAL_HINT, labelX, labelY);
        }
        g.dispose();
    }

    private static class SnapTarget {
        private JigsawPiece piece;
        private boolean afterTarget;
        private double distance;
    }
}
