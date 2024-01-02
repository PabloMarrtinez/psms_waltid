package inf.um.inspection.model;

import inf.um.protos.PabcSerializer;
import inf.um.pairingBLS461.Group1ElementBLS461;
import inf.um.pairingInterfaces.Group1Element;

public class ElGamalCiphertext {
    private Group1Element E1;
    private Group1Element E2;

    public ElGamalCiphertext(Group1Element E1, Group1Element E2) {
        this.E1 = E1;
        this.E2 = E2;
    }

    public ElGamalCiphertext(PabcSerializer.ElGamalCiphertext e) {
        this.E1=new Group1ElementBLS461(e.getE1());
        this.E2=new Group1ElementBLS461(e.getE2());
    }

    public Group1Element getE1() {
        return E1;
    }

    public Group1Element getE2() {
        return E2;
    }


    public PabcSerializer.ElGamalCiphertext toProto() {
        return PabcSerializer.ElGamalCiphertext.newBuilder()
                .setE1(E1.toProto())
                .setE2(E2.toProto())
                .build();
    }
}
