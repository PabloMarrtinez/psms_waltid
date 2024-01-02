package inf.um.psmultisign;

import com.google.protobuf.InvalidProtocolBufferException;
import inf.um.protos.PabcSerializer;
import inf.um.multisign.MSauxArg;
import inf.um.multisign.MSpublicParam;
import org.apache.commons.codec.binary.Base64;

/**
 * Implementation of the public parameters for PS signatures.
 */
public class PSpublicParam implements MSpublicParam {
    private int n;
    private PSauxArg auxArg;

    public PSpublicParam(int n, PSauxArg auxArg) {
        this.n = n;
        this.auxArg = auxArg;
    }

    public PSpublicParam(String publicParam) throws InvalidProtocolBufferException {
        PabcSerializer.PSpublicParam protoPublicParam=PabcSerializer.PSpublicParam.parseFrom(Base64.decodeBase64(publicParam));
        this.n=protoPublicParam.getN();
        this.auxArg=new PSauxArg(protoPublicParam.getAuxArg());
    }

    @Override
    public int getN() {
        return n;
    }

    @Override
    public MSauxArg getAuxArg() {
        return auxArg;
    }

    @Override
    public String getEncoded() {
        return Base64.encodeBase64String(toProto().toByteArray());
    }

    private PabcSerializer.PSpublicParam toProto(){
        return PabcSerializer.PSpublicParam.newBuilder()
                .setN(n)
                .setAuxArg(auxArg.toProto())
                .build();
    }
}
