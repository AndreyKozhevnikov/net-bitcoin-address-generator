using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using static System.Formats.Asn1.AsnWriter;

namespace KeyGenNameSpace {
    public class MySec256 {

        static BigInteger primeModulus = BigInteger.Pow(2, 256) - BigInteger.Pow(2, 32) - BigInteger.Pow(2, 9) - BigInteger.Pow(2, 8) - BigInteger.Pow(2, 7) - BigInteger.Pow(2, 6) - BigInteger.Pow(2, 4) - 1;
        public static byte[] GetPublicKeyNative(byte[] privateKey) {

            //115792089237316195423570985008687907853269984665640564039457584007908834671663


            // generator point (the starting point on the curve used for all calculations)
            Tuple<BigInteger, BigInteger> G = new Tuple<BigInteger, BigInteger>(BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240"), BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424"));

            var tst = BigInteger.Parse("115567090620562097161227597211005235737308125546702379141105501484530475503851");

            var tstBt = tst.ToByteArray();
            var tstBtHx = Convert.ToHexString(tstBt);

            //Array.Reverse(tstBt);
            var tstBtHx2 = Convert.ToHexString(tstBt);

            var tst2 = new BigInteger(tstBt);


            var privHx = Convert.ToHexString(privateKey);


            Array.Reverse(privateKey);
            var privHx2 = Convert.ToHexString(privateKey);

            var newPrivateKey = new byte[33];
            newPrivateKey[32] = 0x0;
            // Array.Reverse(privateKey);
            Array.Copy(privateKey, 0, newPrivateKey, 0, 32);

            var newK = new BigInteger(newPrivateKey);

            var k = new BigInteger(newPrivateKey);
            var point = Multiply(k, G);

            var xArr = point.Item1.ToByteArray();
            //if(xArr.Length < 32) {
            //    return null;
            //}
            var compressed_public_key = new byte[33];
            if(point.Item2 % 2 == 0) {
                compressed_public_key[32] = 0x02;
                // hexX = "02" + hexX;
            } else {
                compressed_public_key[32] = 0x03;
                // hexX = "03" + hexX;
            }
            Array.Copy(xArr, compressed_public_key, Math.Min(32, xArr.Length));
            Array.Reverse(compressed_public_key);


            //var hexX = Convert.ToHexString(compressed_public_key);
            //secp256k1.SecretKeyVerify(privateKey);

            //// Derive public key bytes
            //var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            //secp256k1.PublicKeyCreate(publicKey, privateKey);
            //var publicKeySt = Convert.ToHexString(publicKey);

            //// Serialize the public key to compressed format

            //secp256k1.PublicKeySerialize(compressed_public_key, publicKey, Flags.SECP256K1_EC_COMPRESSED);

            return compressed_public_key;
        }


        public static BigInteger modInverse(BigInteger a, BigInteger n) {
            BigInteger i = n, v = 0, d = 1;
            if(a < 0) {
                a = MyModulus(a, n);
            }

            while(a > 0) {
                BigInteger t = i / a, x = a;
                a = MyModulus(i, x);
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v = MyModulus(v, n);
            if(v < 0) v = MyModulus((v + n), n);
            return v;
        }

        public static BigInteger MyModulus(BigInteger k, BigInteger m) {

            BigInteger n;
            if(k >= 0) {
                n = (k / m);
            } else {
                n = (k / m) - 1; //dirty hack. need to rewrite and/or check
            }
            BigInteger y = k - m * n;
            return y;
        }
        public static Tuple<BigInteger, BigInteger> Double(Tuple<BigInteger, BigInteger> point) {

            // # slope = (3x^2 + a) / 2y    a=0

            //   '/2y' part
            var x3 = 3 * BigInteger.Pow(point.Item1, 2); //++

            var y2 = BigInteger.Multiply(point.Item2, 2); //++


            var y2mod = modInverse(y2, primeModulus);

            var r1 = x3 * y2mod;
            //91914383230618135761690975197207778399550061809281766160147273830617914855857
            var slope = r1 % primeModulus;
            //# new x = slope^2 - 2x
            BigInteger x = (BigInteger.Pow(slope, 2) - (2 * point.Item1)) % primeModulus;

            BigInteger yT0 = (slope * (point.Item1 - x) - point.Item2);

            //12158399299693830322967808612713398636155367887041628176798871954788371653930 
            BigInteger y = MyModulus(yT0, primeModulus);

            return new Tuple<BigInteger, BigInteger>(x, y);
        }
        public static Tuple<BigInteger, BigInteger> Add(Tuple<BigInteger, BigInteger> point1, Tuple<BigInteger, BigInteger> point2) {

            if(point1 == point2) {
                return Double(point1);
            }

            //# slope = (y1 - y2) / (x1 - x2)
            //  slope = ((point1[:y] - point2[:y]) * modinv(point1[:x] - point2[:x])) % $p
            var diffX = point1.Item1 - point2.Item1; //+
            var diffXMod = modInverse(diffX, primeModulus); //-
            var diffY = point1.Item2 - point2.Item2; //+
            var sum = diffY * diffXMod; //-

            BigInteger slope = MyModulus(sum, primeModulus);

            //# new x = slope^2 - x1 - x2
            BigInteger x = MyModulus((BigInteger.Pow(slope, 2) - point1.Item1 - point2.Item1), primeModulus);


            // # new y = slope * (x1 - new x) - y1
            BigInteger y = MyModulus(((slope * (point1.Item1 - x)) - point1.Item2), primeModulus);

            //  var slope = sum % primeModulus;

            return new Tuple<BigInteger, BigInteger>(x, y);
        }


        public static Tuple<BigInteger, BigInteger> Multiply(BigInteger k, Tuple<BigInteger, BigInteger> point) {

            //testzone

            var testM = modInverse(13, 47);

            var testm2 = BigInteger.ModPow(9, 13, 47);

            //testzone

            var current = point;

            //k = BigInteger.Parse("11");

            var bt = k.ToByteArray();
            BitArray bitArray = new BitArray(bt);
            // BitArray binary2 = new BitArray(point.Item1.ToByteArray());

            int i = bitArray.Length - 1;
            while(bitArray[i] == false)
                --i;

            bool[] binary = new bool[i + 1];
            bool[] bitArrayBits = new bool[bitArray.Count];
            bitArray.CopyTo(bitArrayBits, 0);

            Array.Copy(bitArrayBits, binary, i + 1);
            Array.Reverse(binary);

            // var p = point.Item1;
            //p = BigInteger.Parse("123123");


            // ignore first binary character  https://learnmeabitcoin.com/technical/cryptography/elliptic-curve/#multiply

            //# double and add algorithm for fast multiplication
            //int m = 0;
            //using(StreamWriter outputFile = new StreamWriter(Path.Combine("test.txt"))) {
            //    outputFile.WriteLine(k);
            //    outputFile.WriteLine(binary);
            //    for(int j = 1; j < binary.Length; j++) {
            //        outputFile.WriteLine("step " + m++);
            //        //# 0 = double
            //        current = Double(current);
            //        outputFile.WriteLine("after double");
            //        outputFile.WriteLine(current.Item1);
            //        outputFile.WriteLine(current.Item2);


            //        if(binary[j]) {
            //            current = Add(current, point);
            //        }
            //        outputFile.WriteLine("after add");
            //        outputFile.WriteLine(current.Item1);
            //        outputFile.WriteLine(current.Item2);
            //    }
            //}

            for(int j = 1; j < binary.Length; j++) {
                //# 0 = double
                current = Double(current);


                if(binary[j]) {
                    current = Add(current, point);
                }
            }

            return current;

        }
    }
}
