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

        //static BigInteger Modinv(BigInteger x, BigInteger y) {
        //    var a_inverse = BigInteger.ModPow(a, n - 2, n);
        //    return a_inverse;
        //}
        static BigInteger modInverse(BigInteger a, BigInteger n) {
            BigInteger i = n, v = 0, d = 1;
            while(a > 0) {
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if(v < 0) v = (v + n) % n;
            return v;
        }
        static Tuple<BigInteger, BigInteger> Double(Tuple<BigInteger, BigInteger> point) {
            
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
            BigInteger yT1;
            if(yT0 >= 0) {
                yT1 = (yT0 / primeModulus);
            } else {
                yT1 = (yT0 / primeModulus) - 1; //dirty hack. need to rewrite and/or check
            }

            //12158399299693830322967808612713398636155367887041628176798871954788371653930
            BigInteger y = yT0 - primeModulus * yT1;
            //BigInteger yT2 = BigInteger.ModPow(y, primeModulus - 2, primeModulus);

            //var test1 = -5;
            //var test2 = 3;
            //var test3 = test1 % test2;

            return new Tuple<BigInteger, BigInteger>(x, y);
        }
        static Tuple<BigInteger, BigInteger> Add(Tuple<BigInteger, BigInteger> point1, Tuple<BigInteger, BigInteger> point2) {

            if(point1 == point2) {
                return Double(point1);
            }

            //# slope = (y1 - y2) / (x1 - x2)
            //23578750110654438173404407907450265080473019639451825850605815020978465167024
            //  slope = ((point1[:y] - point2[:y]) * modinv(point1[:x] - point2[:x])) % $p
            var diffX = point1.Item1 - point2.Item1;
            var diffXMod=modInverse(diffX, primeModulus); //wrong
            var diffY=point1.Item2 - point2.Item2;
            var sum=diffY*diffXMod;
            var sum2 = diffY / diffX;

            BigInteger slope1;
            if(sum >= 0) {
                slope1 = (sum / primeModulus);
            } else {
                slope1 = (sum / primeModulus) - 1; //dirty hack. need to rewrite and/or check
            }

            //12158399299693830322967808612713398636155367887041628176798871954788371653930
            BigInteger slope = sum - primeModulus * slope1;


          //  var slope = sum % primeModulus;

            return new Tuple<BigInteger, BigInteger>(0, 0);
        }


        static Tuple<BigInteger, BigInteger> Multiply(BigInteger k, Tuple<BigInteger, BigInteger> point) {

            var current = point;

            k = BigInteger.Parse("11");

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
            for(int j = 1; j < binary.Length; j++) {
                //# 0 = double
                current = Double(current);


                if(binary[i]) {
                    current = Add(current, point);
                }

            }

            return current;

        }
    }
}
