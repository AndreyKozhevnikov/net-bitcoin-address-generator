using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace KeyGenNameSpace {
    public class MySec256 {
        public static byte[] GetPublicKeyNative(byte[] privateKey) {

            //115792089237316195423570985008687907853269984665640564039457584007908834671663
            var primeModulus = BigInteger.Pow(2, 256) - BigInteger.Pow(2, 32) - BigInteger.Pow(2, 9) - BigInteger.Pow(2, 8) - BigInteger.Pow(2, 7) - BigInteger.Pow(2, 6) - BigInteger.Pow(2, 4) - 1;

            // generator point (the starting point on the curve used for all calculations)
            Tuple<BigInteger, BigInteger> G = new Tuple<BigInteger, BigInteger>(BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240"), BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424"));

            Array.Reverse(privateKey);
            var k = new BigInteger(privateKey);
            var point = Multiply(k, G);
            //secp256k1.SecretKeyVerify(privateKey);

            //// Derive public key bytes
            //var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            //secp256k1.PublicKeyCreate(publicKey, privateKey);
            //var publicKeySt = Convert.ToHexString(publicKey);

            //// Serialize the public key to compressed format
            var compressed_public_key = new byte[33];
            //secp256k1.PublicKeySerialize(compressed_public_key, publicKey, Flags.SECP256K1_EC_COMPRESSED);

            return compressed_public_key;
        }

       static Tuple<BigInteger,BigInteger> Multiply(BigInteger k, Tuple<BigInteger,BigInteger> point) {

            var current = point;

            k = BigInteger.Parse("11");

             var bt = k.ToByteArray();
             BitArray binary = new BitArray(bt);
             BitArray binary2 = new BitArray(point.Item1.ToByteArray());

            int i = binary.Length - 1;
            while(binary[i] == false)
                --i;

            bool[] bits = new bool[i+1];
            bool[] binaryBits = new bool[binary.Count];
            binary.CopyTo(binaryBits, 0);
          //  binary.CopyTo(bits,i+1); 
            Array.Copy(binaryBits, bits, i + 1);

            // var p = point.Item1;
            //p = BigInteger.Parse("123123");



            return current;

        }
    }
}
