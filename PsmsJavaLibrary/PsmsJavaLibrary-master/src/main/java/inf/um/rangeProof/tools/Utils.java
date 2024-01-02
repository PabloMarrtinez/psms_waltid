package inf.um.rangeProof.tools;

import inf.um.model.mathutils.GroupVector;
import inf.um.pairingInterfaces.Group1Element;
import inf.um.pairingInterfaces.PairingBuilder;
import inf.um.pairingInterfaces.ZpElement;
import inf.um.rangeProof.model.RangeProofBase;

import static inf.um.util.Util.append;

public class Utils {

    public static ZpElement newChallenge(ZpElement previousChallenge, Group1Element l, Group1Element r, PairingBuilder builder) {
        byte[] bytes=previousChallenge.toBytes();
        bytes=append(bytes,l.toBytes());
        bytes=append(bytes,r.toBytes());
        return builder.hashZpElementFromBytes(bytes);
    }


    public static ZpElement newChallenge(ZpElement x, ZpElement tauX, ZpElement mu,PairingBuilder builder) {
        byte[] bytes=x.toBytes();
        bytes=append(bytes,tauX.toBytes());
        bytes=append(bytes,mu.toBytes());
        return builder.hashZpElementFromBytes(bytes);
    }

    public static ZpElement newChallenge(Group1Element v, Group1Element a, Group1Element s, PairingBuilder builder) {
        byte[] bytes=v.toBytes();
        bytes=append(bytes,a.toBytes());
        bytes=append(bytes,s.toBytes());
        return builder.hashZpElementFromBytes(bytes);
    }

    public static RangeProofBase generateRangeProofBase(int n,  String salt, PairingBuilder builder){
        Group1Element[] g=new Group1Element[n];
        Group1Element[] h=new Group1Element[n];
        byte[] saltedBytes=salt.getBytes();
        for(int i=0;i<n;i++){
            g[i]=builder.hashGroup1ElementFromBytes(saltedBytes);
            saltedBytes=g[i].toBytes();
            h[i]=builder.hashGroup1ElementFromBytes(saltedBytes);
            saltedBytes=h[i].toBytes();
        }
        return new RangeProofBase(new GroupVector(g),new GroupVector(h));
    }



}
