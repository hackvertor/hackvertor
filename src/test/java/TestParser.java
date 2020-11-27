import burp.Convertors;
import burp.parser.HackvertorParser;
import burp.parser.ParseException;
import org.json.JSONArray;

import java.util.HashMap;
import java.util.Scanner;

public class TestParser {

    public static void main(String[] args) {
        Scanner input = new Scanner(System.in);
        while (input.hasNext()) {
            System.out.println(Convertors.newConvert(new HashMap<>(), new JSONArray(), input.nextLine()));
        }
    }
}
