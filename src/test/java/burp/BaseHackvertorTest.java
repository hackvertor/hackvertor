package burp;

import burp.hv.Hackvertor;
import burp.hv.HackvertorExtension;
import burp.hv.settings.Settings;
import burp.hv.tags.CustomTags;
import burp.hv.utils.Utils;
import burp.stubs.StubCallbacks;
import burp.stubs.StubExtensionHelpers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;

import javax.swing.*;
import java.io.PrintWriter;
import java.security.Security;

/**
 * Base test class for Hackvertor tests that provides common setUp functionality
 */
public abstract class BaseHackvertorTest {
    
    protected Hackvertor hackvertor;
    
    @BeforeEach
    public void setUp() {
        // Initialize helpers first
        HackvertorExtension.setHelpers(new StubExtensionHelpers());
        
        // Initialize settings and callbacks
        JFrame jFrame = new JFrame("Test");
        StubCallbacks callbacks = new StubCallbacks(jFrame);
        IExtensionHelpers helpers = callbacks.getHelpers();
        
        // Set up HackvertorExtension static fields
        HackvertorExtension.callbacks = callbacks;
        HackvertorExtension.helpers = helpers;
        HackvertorExtension.stderr = new PrintWriter(callbacks.getStderr(), true);
        HackvertorExtension.stdout = new PrintWriter(callbacks.getStdout(), true);
        HackvertorExtension.tagCodeExecutionKey = CustomTags.generateRandomCodeExecutionKey();

        // Generate Hackvertor menu bar
        JMenuBar menuBar = new JMenuBar();
        menuBar.add(Utils.generateHackvertorMenuBar());
        jFrame.setJMenuBar(menuBar);

        // Add security provider
        Security.addProvider(new BouncyCastleProvider());
        
        // Initialize and register settings
        HackvertorExtension.generalSettings = new Settings("general", callbacks);
        Utils.registerGeneralSettings(HackvertorExtension.generalSettings);
        
        // Create Hackvertor instance
        this.hackvertor = new Hackvertor();
    }
}