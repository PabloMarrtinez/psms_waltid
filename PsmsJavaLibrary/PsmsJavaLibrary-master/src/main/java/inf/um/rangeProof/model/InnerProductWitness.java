package inf.um.rangeProof.model;

import inf.um.model.mathutils.ZpVector;

public class InnerProductWitness {

    private ZpVector a;
    private ZpVector b;

    public InnerProductWitness(ZpVector a, ZpVector b) {
        if(a.size()!=b.size())
            throw new IllegalArgumentException("g and h must have the same length");
        this.a = a;
        this.b = b;
    }

    public ZpVector getA() {
        return a;
    }

    public ZpVector getB() {
        return b;
    }

}

