package burp.hv.utils;

import burp.hv.Convertors;
import burp.hv.HackvertorExtension;
import burp.hv.tags.Tag;
import burp.hv.tags.TagArgument;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class ExecutionKeyInUseTests {
    private static final String KEY = "0123456789abcdef0123456789abcdef";
    private String previousKey;

    @BeforeEach
    void setUp() {
        previousKey = HackvertorExtension.tagCodeExecutionKey;
        HackvertorExtension.tagCodeExecutionKey = KEY;
        ExecutionKeyRedactor.resetKeyInUseForTesting();
    }

    @AfterEach
    void tearDown() {
        HackvertorExtension.tagCodeExecutionKey = previousKey;
        ExecutionKeyRedactor.markKeyInUse();
    }

    @Test
    void skipsScanningUntilKeyIsHandedOut() {
        String request = "GET /?x=" + KEY + " HTTP/1.1";
        assertFalse(ExecutionKeyRedactor.containsKey(request));
        assertFalse(ExecutionKeyRedactor.containsKey(request.getBytes(StandardCharsets.US_ASCII)));
        assertSame(request, ExecutionKeyRedactor.redact(request));

        ExecutionKeyRedactor.markKeyInUse();
        assertTrue(ExecutionKeyRedactor.containsKey(request));
        assertFalse(ExecutionKeyRedactor.containsKey(ExecutionKeyRedactor.redact(request)));
    }

    @Test
    void textWithoutKeyDoesNotMarkKeyInUse() {
        ExecutionKeyRedactor.markKeyInUseIfPresent("<@base64>foo</@base64>");
        ExecutionKeyRedactor.markKeyInUseIfPresent(null);
        assertFalse(ExecutionKeyRedactor.isKeyInUse());
    }

    @Test
    void textWithKeyMarksKeyInUse() {
        ExecutionKeyRedactor.markKeyInUseIfPresent("<@python('output = input','" + KEY + "')>");
        assertTrue(ExecutionKeyRedactor.isKeyInUse());
    }

    @Test
    void generatingTagWithoutKeyDoesNotMarkKeyInUse() {
        Tag tag = new Tag(Tag.Category.Encode, "base64", true, "base64(String str)");
        Convertors.generateTagStartEnd(tag);
        assertFalse(ExecutionKeyRedactor.isKeyInUse());
    }

    @Test
    void generatingTagWithKeyMarksKeyInUse() {
        Tag tag = new Tag(Tag.Category.Languages, "python", true, "python(String input, String code, String codeExecuteKey)");
        tag.argument1 = new TagArgument("string", "output = input");
        tag.argument2 = new TagArgument("string", KEY);
        Convertors.generateTagStartEnd(tag);
        assertTrue(ExecutionKeyRedactor.isKeyInUse());
    }
}
