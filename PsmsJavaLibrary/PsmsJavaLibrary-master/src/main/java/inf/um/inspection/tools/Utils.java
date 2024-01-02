package inf.um.inspection.tools;

import inf.um.inspection.model.ElGamalCiphertext;
import inf.um.pairingInterfaces.Group1Element;
import inf.um.pairingInterfaces.PairingBuilder;
import inf.um.pairingInterfaces.ZpElement;

import static inf.um.util.Util.append;

public class Utils {

    public static ZpElement newChallenge(Group1Element v, ElGamalCiphertext E, Group1Element t_v, ElGamalCiphertext t_E, PairingBuilder builder) {
        byte[] bytes=v.toBytes();
        bytes=append(bytes,E.getE1().toBytes());
        bytes=append(bytes,E.getE2().toBytes());
        bytes=append(bytes,t_v.toBytes());
        bytes=append(bytes,t_E.getE1().toBytes());
        bytes=append(bytes,t_E.getE2().toBytes());
        return builder.hashZpElementFromBytes(bytes);
    }

}
