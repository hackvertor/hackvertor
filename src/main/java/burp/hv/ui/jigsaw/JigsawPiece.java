package burp.hv.ui.jigsaw;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.Area;
import java.awt.geom.Ellipse2D;
import java.awt.geom.RoundRectangle2D;
import java.util.ArrayList;
import java.util.List;

public abstract class JigsawPiece extends JPanel {

    static final int KNOB_RADIUS = 9;
    static final int KNOB_CENTRE_Y = 19;
    private static final int CORNER_ARC = 12;
    private static final int MIN_HEIGHT = 38;

    protected final JigsawBoard board;
    private JigsawPiece previous;
    private JigsawPiece next;
    private boolean selected;
    private Point grabPoint;
    private List<JigsawPiece> draggedGroup;

    private final MouseAdapter mouseHandler = new MouseAdapter() {
        @Override
        public void mousePressed(MouseEvent event) {
            board.requestFocusInWindow();
            board.selectPiece(JigsawPiece.this);
            if (event.isPopupTrigger()) {
                board.showPieceMenu(JigsawPiece.this, event);
                return;
            }
            grabPoint = pointInPiece(event);
            detachFromPrevious();
            draggedGroup = chainFromHere();
            board.bringToFront(draggedGroup);
        }

        @Override
        public void mouseDragged(MouseEvent event) {
            if (grabPoint == null) {
                return;
            }
            Point position = SwingUtilities.convertPoint(event.getComponent(), event.getPoint(), board);
            moveGroupTo(position.x - grabPoint.x, position.y - grabPoint.y);
            board.previewDrag(JigsawPiece.this, position);
        }

        @Override
        public void mouseReleased(MouseEvent event) {
            if (event.isPopupTrigger()) {
                board.showPieceMenu(JigsawPiece.this, event);
                return;
            }
            if (grabPoint == null) {
                return;
            }
            grabPoint = null;
            draggedGroup = null;
            board.dropPiece(JigsawPiece.this, SwingUtilities.convertPoint(event.getComponent(), event.getPoint(), board));
        }
    };

    protected JigsawPiece(JigsawBoard board) {
        this.board = board;
        setOpaque(false);
        setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        setBorder(new EmptyBorder(0, KNOB_RADIUS + 6, 0, 6));
        addMouseListener(mouseHandler);
        addMouseMotionListener(mouseHandler);
    }

    protected void makeDraggable(Component component) {
        component.addMouseListener(mouseHandler);
        component.addMouseMotionListener(mouseHandler);
    }

    private Point pointInPiece(MouseEvent event) {
        return SwingUtilities.convertPoint(event.getComponent(), event.getPoint(), this);
    }

    private void moveGroupTo(int x, int y) {
        Rectangle limits = board.dragLimits();
        int deltaX = clamp(x, limits.x, limits.x + Math.max(0, limits.width - getWidth())) - getX();
        int deltaY = clamp(y, limits.y, limits.y + Math.max(0, limits.height - getHeight())) - getY();
        for (JigsawPiece piece : draggedGroup) {
            piece.setLocation(piece.getX() + deltaX, piece.getY() + deltaY);
        }
    }

    private int clamp(int value, int minimum, int maximum) {
        return Math.max(minimum, Math.min(value, maximum));
    }

    public abstract String wrap(String accumulated);

    protected abstract Color fillColour();

    public int bodyWidth() {
        return Math.max(KNOB_RADIUS * 2, getWidth() - KNOB_RADIUS);
    }

    public Point inConnector() {
        return new Point(getX(), getY() + KNOB_CENTRE_Y);
    }

    public Point outConnector() {
        return new Point(getX() + bodyWidth(), getY() + KNOB_CENTRE_Y);
    }

    public JigsawPiece getPrevious() {
        return previous;
    }

    public JigsawPiece getNext() {
        return next;
    }

    public void setNext(JigsawPiece piece) {
        if (next != null) {
            next.previous = null;
        }
        if (piece != null) {
            if (piece.previous != null) {
                piece.previous.next = null;
            }
            piece.previous = this;
        }
        next = piece;
    }

    public void detachFromPrevious() {
        if (previous != null) {
            previous.next = null;
            previous = null;
        }
    }

    public void unlink() {
        detachFromPrevious();
        if (next != null) {
            next.previous = null;
            next = null;
        }
    }

    public JigsawPiece root() {
        JigsawPiece piece = this;
        while (piece.previous != null) {
            piece = piece.previous;
        }
        return piece;
    }

    public JigsawPiece tail() {
        JigsawPiece piece = this;
        while (piece.next != null) {
            piece = piece.next;
        }
        return piece;
    }

    public List<JigsawPiece> chainFromHere() {
        List<JigsawPiece> pieces = new ArrayList<>();
        for (JigsawPiece piece = this; piece != null; piece = piece.next) {
            pieces.add(piece);
        }
        return pieces;
    }

    public boolean isSelected() {
        return selected;
    }

    public void setSelected(boolean selected) {
        this.selected = selected;
        repaint();
    }

    public void refreshSize() {
        setSize(getPreferredSize());
    }

    @Override
    public Dimension getPreferredSize() {
        Dimension size = super.getPreferredSize();
        return new Dimension(size.width + KNOB_RADIUS, Math.max(MIN_HEIGHT, size.height));
    }

    private Area pieceShape() {
        int body = bodyWidth();
        Area area = new Area(new RoundRectangle2D.Double(0.5, 0.5, body - 1, getHeight() - 1, CORNER_ARC, CORNER_ARC));
        area.add(new Area(new Ellipse2D.Double(body - KNOB_RADIUS, KNOB_CENTRE_Y - KNOB_RADIUS, KNOB_RADIUS * 2, KNOB_RADIUS * 2)));
        area.subtract(new Area(new Ellipse2D.Double(-KNOB_RADIUS, KNOB_CENTRE_Y - KNOB_RADIUS, KNOB_RADIUS * 2, KNOB_RADIUS * 2)));
        return area;
    }

    @Override
    protected void paintComponent(Graphics graphics) {
        Graphics2D g = (Graphics2D) graphics.create();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        Area shape = pieceShape();
        Color fill = fillColour();
        g.setColor(fill);
        g.fill(shape);
        g.setColor(selected ? JigsawColours.SELECTION : fill.darker());
        g.setStroke(new BasicStroke(selected ? 2.5f : 1.2f));
        g.draw(shape);
        g.dispose();
    }
}
