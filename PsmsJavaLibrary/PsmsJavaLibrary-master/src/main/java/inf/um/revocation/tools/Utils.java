package inf.um.revocation.tools;

import inf.um.multisign.MSverfKey;
import inf.um.pairingInterfaces.Group1Element;
import inf.um.pairingInterfaces.PairingBuilder;
import inf.um.pairingInterfaces.ZpElement;

import static inf.um.util.Util.append;

public class Utils {
    public static ZpElement newChallenge(Group1Element com1, Group1Element com2, Group1Element t1, Group1Element t2, Group1Element g1, Group1Element h1, Group1Element g2, Group1Element h2, MSverfKey verfKey, PairingBuilder builder) {
        byte[] bytes=com1.toBytes();
        bytes=append(bytes,com1.toBytes());
        bytes=append(bytes,com2.toBytes());
        bytes=append(bytes,t1.toBytes());
        bytes=append(bytes,t2.toBytes());
        bytes=append(bytes,g1.toBytes());
        bytes=append(bytes,h1.toBytes());
        bytes=append(bytes,g2.toBytes());
        bytes=append(bytes,h2.toBytes());
        bytes=append(bytes,verfKey.getEncoded());
        return builder.hashZpElementFromBytes(bytes);
    }

}
