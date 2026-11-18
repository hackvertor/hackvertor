package burp.ui;

import org.assertj.swing.edt.GuiActionRunner;

import javax.swing.*;
import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * Stands in for a real window so the UI tests run with java.awt.headless=true, where no JFrame or
 * java.awt.Robot can be created.
 * <p>
 * The root panel is given a lightweight peer via addNotify(), which is enough for Swing to treat the
 * whole tree as displayable and showing: layout managers run, isShowing() reflects which tab or card
 * is selected and resize events are delivered, just as they would be inside a window on screen.
 */
public final class HeadlessWindow {

    private static final long IDLE_TIMEOUT_MS = 5000;

    private final JPanel root;

    private HeadlessWindow(JPanel root) {
        this.root = root;
    }

    /**
     * Creates a "window" of the given size and lets populate fill it in on the EDT, then waits for any
     * UI work populate queued up (e.g. HackvertorExtension builds its panel with invokeLater).
     */
    public static HeadlessWindow create(int width, int height, Consumer<JPanel> populate) {
        HeadlessWindow window = GuiActionRunner.execute(() -> {
            JPanel root = new JPanel(new BorderLayout());
            root.addNotify();
            root.setSize(width, height);
            populate.accept(root);
            return new HeadlessWindow(root);
        });
        window.waitForIdle();
        return window;
    }

    public JPanel target() {
        return root;
    }

    /**
     * Waits for the event queue to drain, laying out the tree after each pass. Swing's own revalidate()
     * only reaches components inside a real Window, so pending layout is applied here instead.
     */
    public void waitForIdle() {
        EventQueue queue = Toolkit.getDefaultToolkit().getSystemEventQueue();
        long deadline = System.currentTimeMillis() + IDLE_TIMEOUT_MS;
        do {
            GuiActionRunner.execute(root::validate);
        } while (queue.peekEvent() != null && System.currentTimeMillis() < deadline);
    }

    /**
     * Finds the single component under container that matches.
     */
    public Component find(Container container, Predicate<Component> matcher) {
        List<Component> matches = findAll(container, matcher);
        if (matches.size() != 1) {
            throw new AssertionError("Expected exactly one matching component but found " + matches.size() + ": " + matches);
        }
        return matches.get(0);
    }

    public List<Component> findAll(Predicate<Component> matcher) {
        return findAll(root, matcher);
    }

    public List<Component> findAll(Container container, Predicate<Component> matcher) {
        return GuiActionRunner.execute(() -> {
            List<Component> matches = new ArrayList<>();
            collect(container, matcher, matches);
            return matches;
        });
    }

    //Children before their parent, the same order AssertJ's finder returns them in.
    private static void collect(Component component, Predicate<Component> matcher, List<Component> matches) {
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                collect(child, matcher, matches);
            }
        }
        if (matcher.test(component)) {
            matches.add(component);
        }
    }

    /**
     * Left clicks the middle of the component by dispatching the mouse events directly to it. There is
     * no focus without a real window, so a click cannot focus the component the way it would on screen.
     */
    public void click(Component component) {
        GuiActionRunner.execute(() -> {
            int x = component.getWidth() / 2;
            int y = component.getHeight() / 2;
            long when = System.currentTimeMillis();
            component.dispatchEvent(new MouseEvent(component, MouseEvent.MOUSE_PRESSED, when,
                    InputEvent.BUTTON1_DOWN_MASK, x, y, x, y, 1, false, MouseEvent.BUTTON1));
            component.dispatchEvent(new MouseEvent(component, MouseEvent.MOUSE_RELEASED, when,
                    0, x, y, x, y, 1, false, MouseEvent.BUTTON1));
            component.dispatchEvent(new MouseEvent(component, MouseEvent.MOUSE_CLICKED, when,
                    0, x, y, x, y, 1, false, MouseEvent.BUTTON1));
        });
        waitForIdle();
    }

    public void cleanUp() {
        GuiActionRunner.execute(() -> {
            root.removeAll();
            root.removeNotify();
        });
    }
}
