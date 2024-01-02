package inf.um.rangeProof;

import inf.um.protos.PabcSerializer;
import inf.um.pairingBLS461.Group1ElementBLS461;
import inf.um.pairingInterfaces.Group1Element;
import inf.um.rangeProof.model.RangeProof;

public class RangePredicateToken {
    private RangeProof proofLowerBound;
    private RangeProof proofUpperBound;
    private Group1Element commitV;

    public RangePredicateToken(RangeProof proofLowerBound, RangeProof proofUpperBound, Group1Element commitV) {
        this.proofLowerBound = proofLowerBound;
        this.proofUpperBound = proofUpperBound;
        this.commitV = commitV;
    }

    public RangePredicateToken(PabcSerializer.RangePredToken rangePredToken) {
        if(rangePredToken.hasProofLowerBound())
            this.proofLowerBound=new RangeProof(rangePredToken.getProofLowerBound());
        if(rangePredToken.hasProofUpperBound())
            this.proofUpperBound=new RangeProof(rangePredToken.getProofUpperBound());
        this.commitV=new Group1ElementBLS461(rangePredToken.getCommitV());
    }

    public RangeProof getProofLowerBound() {
        return proofLowerBound;
    }

    public RangeProof getProofUpperBound() {
        return proofUpperBound;
    }

    public Group1Element getCommitV() {
        return commitV;
    }

    public PabcSerializer.RangePredToken toProto() {
        PabcSerializer.RangePredToken.Builder builder=PabcSerializer.RangePredToken.newBuilder().setCommitV(commitV.toProto());
        if(proofLowerBound!=null)
            builder.setProofLowerBound(proofLowerBound.toProto());
        if(proofUpperBound!=null)
            builder.setProofUpperBound(proofUpperBound.toProto());
        return builder.build();
    }
}
