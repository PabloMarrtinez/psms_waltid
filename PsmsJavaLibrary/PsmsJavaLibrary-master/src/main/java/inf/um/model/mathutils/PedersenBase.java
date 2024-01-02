package inf.um.model.mathutils;

import inf.um.pairingInterfaces.Group1Element;

public class PedersenBase {
    private Group1Element g;
    private Group1Element h;

    public PedersenBase(Group1Element g, Group1Element h) {
        this.g = g;
        this.h = h;
    }

    public Group1Element getG() {
        return g;
    }

    public Group1Element getH() {
        return h;
    }

}
