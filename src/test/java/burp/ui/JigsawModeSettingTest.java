package burp.ui;

import burp.hv.Hackvertor;
import burp.hv.HackvertorExtension;
import burp.hv.settings.JigsawModeSetting;
import burp.hv.settings.Settings;
import burp.hv.tags.CustomTags;
import burp.hv.ui.HackvertorPanel;
import burp.hv.utils.Utils;
import burp.stubs.StubCallbacks;
import burp.stubs.StubExtensionHelpers;
import burp.stubs.StubMontoyaApi;
import org.assertj.swing.edt.GuiActionRunner;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JigsawModeSettingTest {

    private static Hackvertor hackvertor;

    @BeforeAll
    static void setUp() {
        hackvertor = GuiActionRunner.execute(() -> {
            HackvertorExtension.setHelpers(new StubExtensionHelpers());
            StubCallbacks callbacks = new StubCallbacks(new JFrame("Test"));
            HackvertorExtension.callbacks = callbacks;
            HackvertorExtension.helpers = callbacks.getHelpers();
            HackvertorExtension.stderr = new PrintWriter(callbacks.getStderr(), true);
            HackvertorExtension.stdout = new PrintWriter(callbacks.getStdout(), true);
            HackvertorExtension.tagCodeExecutionKey = CustomTags.generateRandomCodeExecutionKey();
            HackvertorExtension.generalSettings = new Settings("general", callbacks);
            Utils.registerGeneralSettings(HackvertorExtension.generalSettings);
            return new Hackvertor();
        });
    }

    @BeforeEach
    void freshPreferences() {
        HackvertorExtension.montoyaApi = StubMontoyaApi.withInMemoryPersistence();
    }

    @AfterAll
    static void tearDown() {
        HackvertorExtension.montoyaApi = null;
    }

    @Test
    void panelsStartInJigsawModeWhenNothingIsStored() {
        assertTrue(JigsawModeSetting.isJigsawMode());
        assertTrue(jigsawCardIsShown(panel()));
    }

    @Test
    void switchingModeIsStoredAsAPreference() {
        HackvertorPanel panel = panel();
        selectMode(panel, "Tag mode");
        assertFalse(JigsawModeSetting.isJigsawMode());
        selectMode(panel, "Jigsaw mode");
        assertTrue(JigsawModeSetting.isJigsawMode());
    }

    @Test
    void newPanelsUseTheRememberedMode() {
        selectMode(panel(), "Tag mode");
        assertFalse(jigsawCardIsShown(panel()));
        selectMode(panel(), "Jigsaw mode");
        assertTrue(jigsawCardIsShown(panel()));
    }

    private HackvertorPanel panel() {
        return GuiActionRunner.execute(() -> new HackvertorPanel(hackvertor, false, false, false));
    }

    private boolean jigsawCardIsShown(HackvertorPanel panel) {
        return GuiActionRunner.execute(() ->
                SwingUtilities.getAncestorOfClass(JScrollPane.class, panel.getJigsawBoard()).isVisible());
    }

    private void selectMode(HackvertorPanel panel, String mode) {
        GuiActionRunner.execute(() -> {
            findSelector(panel).setSelectedItem(mode);
            return null;
        });
    }

    private JComboBox<?> findSelector(Container container) {
        for (Component component : container.getComponents()) {
            if (component instanceof JComboBox && "inputModeSelector".equals(component.getName())) {
                return (JComboBox<?>) component;
            }
            if (component instanceof Container) {
                JComboBox<?> nested = findSelector((Container) component);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }
}
