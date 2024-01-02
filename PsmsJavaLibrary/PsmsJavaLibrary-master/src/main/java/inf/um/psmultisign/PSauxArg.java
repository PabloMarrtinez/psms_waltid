package inf.um.psmultisign;

import inf.um.protos.PabcSerializer;
import inf.um.multisign.MSauxArg;

import java.util.HashSet;
import java.util.Set;

/**
 * Specific auxiliary arguments needed for PS scheme setup.
 */
public class PSauxArg implements MSauxArg {
    private String pairingName;
    private Set<String> attributes;

    public PSauxArg(String pairingName, Set<String> attributes) {
        this.pairingName = pairingName;
        this.attributes = attributes;
    }

    public PSauxArg(PabcSerializer.PSauxArg auxArg) {
        this.pairingName = auxArg.getPairingName();
        this.attributes = new HashSet<>();
        attributes.addAll(auxArg.getAttributesList());
    }

    public String getPairingName() {
        return pairingName;
    }

    public Set<String> getAttributes() {
        return attributes;
    }

    public PabcSerializer.PSauxArg toProto(){
        return PabcSerializer.PSauxArg.newBuilder()
                .setPairingName(pairingName)
                .addAllAttributes(attributes)
                .build();
    }
}
