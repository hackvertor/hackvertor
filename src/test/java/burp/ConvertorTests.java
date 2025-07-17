package burp;
import burp.hv.Hackvertor;
import burp.hv.HackvertorExtension;
import burp.stubs.StubExtensionHelpers;
import org.junit.jupiter.api.Test;

import javax.swing.*;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ConvertorTests {

    private final Hackvertor hackvertor;

    public ConvertorTests() {
        JFrame jFrame = new JFrame("Burp Suite - Hackvertor");
        HackvertorExtension hvExtension = new HackvertorExtension();
        hvExtension.registerExtenderCallbacks(new burp.stubs.StubCallbacks(jFrame));
        this.hackvertor = new Hackvertor();
        HackvertorExtension.setHelpers(new StubExtensionHelpers());
    }

    @Test
    void convertSpaceInTag() {
        String spaceInContent = "<@base64> </@base64>";
        String converted = hackvertor.convert(spaceInContent, hackvertor);
        assertEquals("IA==", converted);
    }

    @Test
    void testBase64Encoding() {
        String input = "<@base64>test</@base64>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("dGVzdA==", converted);
    }

    @Test
    void testSpaceInAttribute(){
        String plaintext = "<@ascii2hex('')>abcd</@ascii2hex>";
        assertEquals("61626364", hackvertor.convert(plaintext, hackvertor));
        plaintext = "<@ascii2hex(' ')>abcd</@ascii2hex>";
        assertEquals("61 62 63 64", hackvertor.convert(plaintext, hackvertor));
        plaintext = "<@ascii2hex('  ')>abcd</@ascii2hex>";
        assertEquals("61  62  63  64", hackvertor.convert(plaintext, hackvertor));
    }
}