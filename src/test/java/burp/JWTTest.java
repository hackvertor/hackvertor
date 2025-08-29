package burp;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for JWT tag functionality
 */
public class JWTTest extends BaseHackvertorTest {

    @Test
    void testJWTWithHS256() {
        // Test the exact example from the bug report
        String input = "<@jwt('HS256','a-string-secret-at-least-256-bits-long')>{\n" +
                "  \"sub\": \"1234567890\",\n" +
                "  \"name\": \"John Doe\",\n" +
                "  \"admin\": true,\n" +
                "  \"iat\": 1516239022\n" +
                "}</@jwt>";
        
        String expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
        
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals(expected, converted, "JWT token should match expected output with correct header field order");
        
        // Verify the header has correct field order
        String[] parts = converted.split("\\.");
        assertEquals(3, parts.length, "JWT should have three parts");
        
        // The header should be: {"alg":"HS256","typ":"JWT"}
        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", parts[0], 
            "JWT header should have 'alg' before 'typ'");
    }
    
    @Test
    void testJWTWithHS384() {
        String input = "<@jwt('HS384','your-384-bit-secret')>{\n" +
                "  \"sub\": \"user123\",\n" +
                "  \"name\": \"Alice\",\n" +
                "  \"iat\": 1516239022\n" +
                "}</@jwt>";
        
        String converted = hackvertor.convert(input, hackvertor);
        assertNotNull(converted);
        
        // Verify it's a valid JWT format
        String[] parts = converted.split("\\.");
        assertEquals(3, parts.length, "JWT should have three parts");
        
        // Verify header starts correctly (should decode to {"alg":"HS384","typ":"JWT"})
        String headerB64 = parts[0];
        assertTrue(headerB64.startsWith("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9"),
            "Header should have correct field order with HS384");
    }
    
    @Test
    void testJWTWithHS512() {
        String input = "<@jwt('HS512','your-512-bit-secret')>{\n" +
                "  \"sub\": \"user456\",\n" +
                "  \"name\": \"Bob\",\n" +
                "  \"iat\": 1516239022\n" +
                "}</@jwt>";
        
        String converted = hackvertor.convert(input, hackvertor);
        assertNotNull(converted);
        
        // Verify it's a valid JWT format
        String[] parts = converted.split("\\.");
        assertEquals(3, parts.length, "JWT should have three parts");
        
        // Verify header starts correctly (should decode to {"alg":"HS512","typ":"JWT"})
        String headerB64 = parts[0];
        assertTrue(headerB64.startsWith("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"),
            "Header should have correct field order with HS512");
    }
    
    @Test
    void testJWTWithNoneAlgorithm() {
        String input = "<@jwt('NONE','')>{\n" +
                "  \"sub\": \"user789\",\n" +
                "  \"name\": \"Charlie\"\n" +
                "}</@jwt>";
        
        String converted = hackvertor.convert(input, hackvertor);
        assertNotNull(converted);
        
        // Verify it's a valid JWT format with no signature
        // For NONE algorithm, the JWT ends with a single dot (header.payload.)
        // which when split results in 2 parts, not 3
        assertTrue(converted.endsWith("."), "JWT with 'none' algorithm should end with a dot");
        String[] parts = converted.split("\\.");
        assertEquals(2, parts.length, "JWT with 'none' algorithm splits into 2 parts when ending with single dot");
        
        // Verify header has correct field order
        String headerB64 = parts[0];
        assertTrue(headerB64.startsWith("eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0"),
            "Header should have correct field order with NONE algorithm");
    }
    
    @Test
    void testJWTWithBlankSecret() {
        // Test JWT with empty/blank secret (insecure but sometimes used)
        String input = "<@jwt('HS256','')>{\n" +
                "  \"sub\": \"1234567890\",\n" +
                "  \"name\": \"John Doe\",\n" +
                "  \"admin\": true,\n" +
                "  \"iat\": 1516239022\n" +
                "}</@jwt>";
        
        String expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.7TNtfdcRCraA6JxwuKlByAryTktb653DD-Ve951DHSY";
        
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals(expected, converted, "JWT with blank secret should match expected output");
        
        // Verify structure
        String[] parts = converted.split("\\.");
        assertEquals(3, parts.length, "JWT should have three parts");
        
        // Verify header is still correct
        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", parts[0], 
            "JWT header should be standard even with blank secret");
    }
    
    @Test
    void testJWTWithComplexPayload() {
        String input = "<@jwt('HS256','secret')>{\n" +
                "  \"iss\": \"https://example.com\",\n" +
                "  \"sub\": \"1234567890\",\n" +
                "  \"aud\": [\"api1\", \"api2\"],\n" +
                "  \"exp\": 1640995200,\n" +
                "  \"nbf\": 1640908800,\n" +
                "  \"iat\": 1640908800,\n" +
                "  \"jti\": \"unique-token-id\",\n" +
                "  \"custom_claim\": \"custom_value\",\n" +
                "  \"nested\": {\n" +
                "    \"key\": \"value\"\n" +
                "  }\n" +
                "}</@jwt>";
        
        String converted = hackvertor.convert(input, hackvertor);
        assertNotNull(converted);
        
        // Verify it's a valid JWT format
        String[] parts = converted.split("\\.");
        assertEquals(3, parts.length, "JWT should have three parts");
        
        // Verify header has correct structure
        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", parts[0],
            "Header should be consistent regardless of payload");
    }
    
    @Test
    void testJWTWithInvalidAlgorithm() {
        String input = "<@jwt('INVALID','secret')>{\"sub\":\"test\"}</@jwt>";
        
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Unsupported algorithm", converted,
            "Should return error message for unsupported algorithm");
    }
    
    @Test
    void testJWTWithMalformedJSON() {
        String input = "<@jwt('HS256','secret')>not valid json</@jwt>";
        
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Unable to create token", converted,
            "Should return error message for invalid JSON payload");
    }
}