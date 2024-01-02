package inf.um.util;

import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.BLS;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.HASH512;
import org.miracl.core.RAND;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public  class SoftwareCommonCrypto implements CommonCrypto {
  protected final Random rand;
  protected final RAND rng = new RAND();

  public SoftwareCommonCrypto(Random random) {
    this.rand = random;
    byte[] seed = new byte[CommonCrypto.COMPUTATION_SEC_BYTES];
    rand.nextBytes(seed);
    rng.seed(CommonCrypto.COMPUTATION_SEC_BYTES, seed);
  }

  @Override
  public BigInteger hashToBigInteger(List<byte[]> input, BigInteger modulus) {
    return hashToBigIntegerSha512(input, modulus);
  }
  public static BigInteger hashToBigIntegerSha512(List<byte[]> input, BigInteger modulus) {
    int blocksNeeded = 1+((modulus.bitLength() + STATISTICAL_SEC_BYTES * 8) / 512);
    ByteBuffer digestData = ByteBuffer.allocate(blocksNeeded*512/8);
    for (int i = 0; i < blocksNeeded; i++) {
      byte[] index = ByteBuffer.allocate(4).putInt(i).array();
      List<byte[]> toHash = new ArrayList<>(input);
      toHash.add(index);
      digestData.put(hashListUsingSha512(toHash));
    }
    BigInteger result = new BigInteger(1, digestData.array());
    return result.mod(modulus);
  }


  @Override
  public byte[] hashList(List<byte[]> input) {
    return hashListUsingSha512(input);
  }
  public static byte[] hashListUsingSha512(List<byte[]> input) {
    // Hash each element individually and then has the list of digests
    // to ensure no two list hash to the same value,
    // even if the bits of the individual elements are the same when flattened
    HASH512 h = new HASH512();
    for(byte[] b: input) {
      h.process_array(hashSingleElementSha512(b));
    }
    return h.hash();
  }

  @Override
  public byte[] hashSingleElement(byte[] input) {
    return hashSingleElementSha512(input);
  }
  public static byte[] hashSingleElementSha512(byte[] input){
    HASH512 h = new HASH512();
    h.process_array(input);
    return h.hash();
  }

  @Override
  public byte[] getBytes(int noOfBytes) {
    byte[] bytes = new byte[noOfBytes];
    rand.nextBytes(bytes);
    return bytes;
  }

  @Override
  public boolean verifySignature(PublicKey publicKey, byte[] input, byte[] signature) {
    try {
      Signature sig = null;
      if("RSA".equals(publicKey.getAlgorithm())) {
        sig = Signature.getInstance("SHA256withRSA");
      } else {
        sig = Signature.getInstance("SHA256withECDSA");
      }
      sig.initVerify(publicKey);
      sig.update(input);
      return sig.verify(signature);
    } catch(Exception e) {
      return false;
    }
  }

  @Override
  public boolean verifySignature(PublicKey publicKey, List<byte[]> input, byte[] signature) {
    return verifySignature(publicKey, hashList(input), signature);
  }

  @Override
  public BIG getRandomNumber() {
    return BIG.random(rng);
  }

  @Override
  public ECP hashToGroup1Element(byte[] input) {
    return BLS.bls_hash_to_point(input);
  }

}
