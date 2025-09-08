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
import org.junit.jupiter.api.AfterEach;

import javax.swing.*;
import java.io.PrintWriter;
import java.security.Security;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Base test class for Hackvertor tests that provides common setUp functionality
 */
public abstract class BaseHackvertorTest {
    
    protected Hackvertor hackvertor;
    private Thread.UncaughtExceptionHandler originalHandler;
    private final ConcurrentLinkedQueue<Throwable> uncaughtExceptions = new ConcurrentLinkedQueue<>();
    
    @BeforeEach
    public void setUp() {
        // Set up uncaught exception handler to catch any Java exceptions
        originalHandler = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, exception) -> {
            uncaughtExceptions.offer(exception);
            // Also call original handler if it exists
            if (originalHandler != null) {
                originalHandler.uncaughtException(thread, exception);
            }
        });
        
        // Clear any previous exceptions
        uncaughtExceptions.clear();
        
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
    
    @AfterEach
    public void tearDown() {
        // Check for uncaught exceptions and fail the test if any occurred
        if (!uncaughtExceptions.isEmpty()) {
            StringBuilder sb = new StringBuilder("Test failed due to uncaught exception(s):\n");
            for (Throwable exception : uncaughtExceptions) {
                sb.append("- ").append(exception.getClass().getSimpleName())
                  .append(": ").append(exception.getMessage()).append("\n");
                if (exception.getCause() != null) {
                    sb.append("  Caused by: ").append(exception.getCause().getClass().getSimpleName())
                      .append(": ").append(exception.getCause().getMessage()).append("\n");
                }
            }
            
            // Restore original handler before failing
            Thread.setDefaultUncaughtExceptionHandler(originalHandler);
            
            fail(sb.toString());
        }
        
        // Restore original exception handler
        Thread.setDefaultUncaughtExceptionHandler(originalHandler);
    }
}