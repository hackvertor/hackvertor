import burp.parser.HackvertorParser;
import burp.parser.ParseException;

import java.util.Scanner;

public class TestParser {

    public static void main(String[] args) {
        Scanner input = new Scanner(System.in);
        while (input.hasNext()) {
            try {
                HackvertorParser.parse(input.nextLine());
            } catch (ParseException e) {
                e.printStackTrace();
            }
        }
    }
}
