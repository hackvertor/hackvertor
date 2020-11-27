import burp.Convertors;
import burp.parser.HackvertorParser;
import burp.parser.ParseException;
import org.json.JSONArray;

import java.util.HashMap;
import java.util.Scanner;

public class TestParser {

    public static void main(String[] args) {
        String test = ">VALUE<@/set_B\n" +
                "<@get(\"B\")>FALLBACK<@/get>\n" +
                "<@get(\"B\") />a";

        try {
            System.out.println(HackvertorParser.parse(test));
        } catch (ParseException e) {
            e.printStackTrace();
        }

        Scanner input = new Scanner(System.in);
        while (input.hasNext()) {
            System.out.println(Convertors.newConvert(new HashMap<>(),
                    new JSONArray(), input.nextLine()));
        }
    }
}
