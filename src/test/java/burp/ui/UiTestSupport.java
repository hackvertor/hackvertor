package burp.ui;

import org.assertj.swing.edt.GuiActionRunner;
import org.assertj.swing.fixture.FrameFixture;

import javax.swing.*;

public class UiTestSupport {

    public static final String TAG_MODE = "Tag mode";
    public static final String JIGSAW_MODE = "Jigsaw mode";

    public static void selectInputMode(FrameFixture window, String mode) {
        JComboBox<?> selector = (JComboBox<?>) window.robot().finder().find(window.target(),
                component -> component instanceof JComboBox && "inputModeSelector".equals(component.getName()));
        GuiActionRunner.execute(() -> selector.setSelectedItem(mode));
        window.robot().waitForIdle();
    }
}
