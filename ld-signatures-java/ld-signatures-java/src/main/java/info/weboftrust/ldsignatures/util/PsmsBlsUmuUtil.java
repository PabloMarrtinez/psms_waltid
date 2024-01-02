package info.weboftrust.ldsignatures.util;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class PsmsBlsUmuUtil {
    private static final Set<String> excludedPredicates = new HashSet<>(Arrays.asList(
            "http://purl.org/dc/terms/created",
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
            "https://w3id.org/security#proofPurpose",
            "https://w3id.org/security#verificationMethod"
    ));
    public static String processRdfData(String rdfData) {
        StringBuilder result = new StringBuilder();
        String[] lines = rdfData.split("\n");

        for (String line : lines) {
            if (!isLineExcluded(line)) {
                result.append(line).append("\n");
            }
        }

        return result.toString();
    }

    private static boolean isLineExcluded(String line) {
        for (String predicate : excludedPredicates) {
            if (line.contains(predicate)) {
                return true;
            }
        }
        return false;
    }
}
