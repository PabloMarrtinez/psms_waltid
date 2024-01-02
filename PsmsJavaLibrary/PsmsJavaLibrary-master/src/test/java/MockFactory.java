import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import inf.um.multisign.MSauxArg;
import inf.um.multisign.MSmessage;
import inf.um.multisign.MSpublicParam;
import inf.um.multisign.MSsignature;
import inf.um.multisign.MSverfKey;
import inf.um.multisign.MSzkToken;
import inf.um.pairingInterfaces.Group1Element;
import inf.um.pairingInterfaces.Group2Element;
import inf.um.pairingInterfaces.Group3Element;
import inf.um.pairingInterfaces.ZpElement;

public class MockFactory {

    public static MSauxArg mockMsAuxArg() {
        return mock(MSauxArg.class);
    }

    public static MSmessage mockMsMessage() {
        return mock(MSmessage.class);
    }

    public static MSpublicParam mockPublicParam() {
        MSpublicParam mockPubParam = mock(MSpublicParam.class);
        doReturn(0).when(mockPubParam).getN();
        return mockPubParam;
    }

    public static MSsignature mockSig() {
        return mock(MSsignature.class);
    }

    public static MSverfKey mockVerfKey() {
        MSverfKey verfKey = mock(MSverfKey.class);
        doReturn(new byte[0]).when(verfKey).getEncoded();
        return verfKey;
    }

    public static MSzkToken mockZkToken() {
        return mock(MSzkToken.class);
    }

    public static Group1Element mockGroup1Element() {
        Group1Element mock = mock(Group1Element.class);
        doReturn(false).when(mock).isUnity();
        return mock;
    }

    public static Group2Element mockGroup2Element() {
        Group2Element mock = mock(Group2Element.class);
        doReturn(false).when(mock).isUnity();
        return mock;
    }

    public static Group3Element mockGroup3Element() {
        Group3Element mock = mock(Group3Element.class);
        doReturn(false).when(mock).isUnity();
        return mock;
    }

    public static ZpElement mockZpElement() {
        ZpElement mock = mock(ZpElement.class);
        doReturn(false).when(mock).isUnity();
        return mock;
    }
}
