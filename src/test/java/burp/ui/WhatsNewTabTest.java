package burp.ui;

import burp.hv.Hackvertor;
import burp.hv.HackvertorExtension;
import burp.hv.settings.Settings;
import burp.hv.tags.CustomTags;
import burp.hv.ui.ExtensionPanel;
import burp.hv.ui.HackvertorPanel;
import burp.hv.ui.WhatsNewPanel;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The What's new tab is a fixed tab, so it must survive the add/close/restore flows that assume
 * the tab strip is nothing but user convertor tabs followed by "...".
 */
public class WhatsNewTabTest {

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

    private ExtensionPanel panel() {
        return GuiActionRunner.execute(() -> new ExtensionPanel(hackvertor));
    }

    private static String[] titles(ExtensionPanel panel) {
        return GuiActionRunner.execute(() -> {
            String[] result = new String[panel.getTabCount()];
            for (int i = 0; i < panel.getTabCount(); i++) {
                result[i] = panel.getTitleAt(i);
            }
            return result;
        });
    }

    @Test
    void whatsNewIsTheLastTab() {
        assertTabTitles(new String[]{"1", "...", WhatsNewPanel.TITLE}, titles(panel()));
    }

    @Test
    void whatsNewTabHasNoCloseButton() {
        ExtensionPanel panel = panel();
        int index = GuiActionRunner.execute(() -> panel.indexOfTab(WhatsNewPanel.TITLE));
        //A closable tab gets a CloseButtonTab component, a fixed tab gets none.
        assertNull(GuiActionRunner.execute(() -> panel.getTabComponentAt(index)));
        assertNotNull(GuiActionRunner.execute(() -> panel.getTabComponentAt(panel.indexOfTab("1"))));
    }

    @Test
    void whatsNewTabHoldsTheWhatsNewPanel() {
        ExtensionPanel panel = panel();
        Component component = GuiActionRunner.execute(
                () -> panel.getComponentAt(panel.indexOfTab(WhatsNewPanel.TITLE)));
        assertInstanceOf(WhatsNewPanel.class, component);
    }

    @Test
    void selectingTheDotsTabAddsAConvertorTabBeforeIt() {
        ExtensionPanel panel = panel();
        GuiActionRunner.execute(() -> panel.setSelectedIndex(panel.indexOfTab("...")));
        assertTabTitles(new String[]{"1", "2", "...", WhatsNewPanel.TITLE}, titles(panel));
        assertInstanceOf(HackvertorPanel.class, GuiActionRunner.execute(panel::getSelectedConvertorPanel));
    }

    @Test
    void addNewPanelInsertsBeforeTheDotsTab() {
        ExtensionPanel panel = panel();
        GuiActionRunner.execute(panel::addNewPanel);
        GuiActionRunner.execute(panel::addNewPanel);
        assertTabTitles(new String[]{"1", "2", "3", "...", WhatsNewPanel.TITLE}, titles(panel));
    }

    @Test
    void closingATabLandsOnAConvertorTabNotAFixedTab() {
        ExtensionPanel panel = panel();
        GuiActionRunner.execute(panel::addNewPanel);
        GuiActionRunner.execute(() -> {
            Component doomed = panel.getComponentAt(panel.indexOfTab("2"));
            panel.clickedDelete = true;
            panel.remove(doomed);
        });
        assertTabTitles(new String[]{"1", "...", WhatsNewPanel.TITLE}, titles(panel));
        assertNotNull(GuiActionRunner.execute(panel::getSelectedConvertorPanel));
    }

    @Test
    void closingTheLastConvertorTabCreatesAFreshOne() {
        ExtensionPanel panel = panel();
        GuiActionRunner.execute(() -> {
            Component doomed = panel.getComponentAt(panel.indexOfTab("1"));
            panel.clickedDelete = true;
            panel.remove(doomed);
        });
        assertNotNull(GuiActionRunner.execute(panel::getSelectedConvertorPanel));
        assertTrue(GuiActionRunner.execute(() -> panel.indexOfTab(WhatsNewPanel.TITLE)) >= 0);
    }

    @Test
    void savingAndRestoringKeepsTheFixedTabsAndSkipsThemInTheState() {
        ExtensionPanel panel = panel();
        GuiActionRunner.execute(panel::addNewPanel);
        GuiActionRunner.execute(() -> {
            panel.getSelectedConvertorPanel().getInputArea().setText("kept");
            panel.saveState();
        });

        ExtensionPanel restored = panel();
        GuiActionRunner.execute(restored::restoreState);
        assertTabTitles(new String[]{"1", "2", "...", WhatsNewPanel.TITLE}, titles(restored));
        assertEquals("kept", GuiActionRunner.execute(
                () -> ((HackvertorPanel) restored.getComponentAt(restored.indexOfTab("2"))).getInputArea().getText()));
    }

    @Test
    void refreshDoesNotBlowUpWhileWhatsNewIsSelected() {
        ExtensionPanel panel = panel();
        GuiActionRunner.execute(() -> {
            panel.setSelectedIndex(panel.indexOfTab(WhatsNewPanel.TITLE));
            panel.refresh();
        });
        assertNull(GuiActionRunner.execute(panel::getSelectedConvertorPanel));
    }

    private static void assertTabTitles(String[] expected, String[] actual) {
        assertEquals(String.join(" | ", expected), String.join(" | ", actual), "tab strip");
    }
}
