using NUnit.Framework;
using KeyGenNameSpace;
using Org.BouncyCastle.Math;
using System.Numerics;
using Newtonsoft.Json.Linq;
using BigInteger = System.Numerics.BigInteger;

namespace TestsKeyGenerator {
    [TestFixture]
    public class HashConverterTest {
        [Test]
        public void TestPriv() {


            var input = "enter credit long demand tortoise harsh frame path rifle news then trigger";
            var res = new KeyGen().GenerateFromString(input);
            Assert.AreEqual("9DDB55473EFFB85D2AF6E24B99ADE223A4E6F932D4933BDD4722B692B744CD23", res.PrivateKey);


        }
        [Test]
        public void TestWif() {
            var input = "enter credit long demand tortoise harsh frame path rifle news then trigger";
            var res = new KeyGen().GenerateFromString(input);
            Assert.AreEqual("L2WZevbYBAtLKbK76UNVu4sjqyibc3kc2qS6Qxwvpt5dhk35W19E", res.WIF);


        }
        [Test]
        public void Test1adr() {
            var input = "enter credit long demand tortoise harsh frame path rifle news then trigger";
            var res = new KeyGen().GenerateFromString(input);

            var hasAdr = res.Addresses.Contains("1CUuQXtKLY4XoEbHZ9BexWLZfN7wUHPuXC");
            Assert.AreEqual(true, hasAdr);
        }
        [Test]
        public void Test3adr() {
            var input = "enter credit long demand tortoise harsh frame path rifle news then trigger";
            var res = new KeyGen().GenerateFromString(input);

            var hasAdr = res.Addresses.Contains("3KJq5p2MtPyV4i6yJRboxNkXCob197MiJj");
            Assert.AreEqual(true, hasAdr);
        }
        [Test]
        public void TestBCadr() {
            var input = "enter credit long demand tortoise harsh frame path rifle news then trigger";
            var res = new KeyGen().GenerateFromString(input);

            var hasAdr = res.Addresses.Contains("bc1q0hc9c4jh39nz2tf8plsyfjsajthg4x4uza7u40");
            Assert.AreEqual(true, hasAdr);
        }
        [Test]
        public void TestString() {
            var input = "test";
            var res = new KeyGen().GenerateFromString(input);
            Assert.AreEqual("L2ZovMyTxxQVJmMtfQemgVcB5YmiEDapDwsvX6RqvuWibgUNRiHz", res.WIF);

        }
        [Test]
        public void TestInt() {
            var res = new KeyGen().GenerateFromInt(1155);
            Assert.AreEqual("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUGxXgtm63M", res.WIF);
        }
        [Test]
        public void TestInt3() {
            var res = new KeyGen().GenerateFromInt(3);
            Assert.AreEqual("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S", res.WIF);
        }
        [Test]
        public void TestBigInt() {
            var val = System.Numerics.BigInteger.Parse("30568377312064202855");
            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GenerateFromBigInt(val);
            Assert.AreEqual("18ZMbwUFLMHoZBbfpCjUJQTCMCbktshgpe", res.Addresses[0]);
        }


        [Test]
        public void GetPublicKeyWithsecp256k1() {
            byte[] intBytes = BitConverter.GetBytes(3);
            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);


            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKey(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithsecp256k1_1() {
            byte[] intBytes = BitConverter.GetBytes(11);
            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);


            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKey(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithsecp256k1_2() {
            byte[] intBytes = BitConverter.GetBytes(3464879846);
            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);


            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKey(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("0222c6cde840c26dab252ce847e81bfa3fe7fa59c5cfb5879337a0e6117205837b", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithsecp256k1_3() {
            byte[] intBytes = BitConverter.GetBytes(1234);
            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);


            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKey(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("02e37648435c60dcd181b3d41d50857ba5b5abebe279429aa76558f6653f1658f2", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithsecp256k1_4() {
            byte[] intBytes = BitConverter.GetBytes(235);
            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);


            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKey(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("02d5e9e1da649d97d89e4868117a465a3a4f8a18de57a140d36b3f2af341a21b52", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithsecp256k1_5() {
            byte[] intBytes = BitConverter.GetBytes(56);
            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);


            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKey(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("02bce74de6d5f98dc027740c2bbff05b6aafe5fd8d103f827e48894a2bd3460117", compressed_public_key_st);
        }

        [Test]
        public void GetPublicKeyWithsecp256k1_6() {
            byte[] intBytes = BitConverter.GetBytes(123);
            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);


            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKey(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithsecp256k1_7() {
            byte[] intBytes = BitConverter.GetBytes(2125123);
            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);


            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKey(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("039840c46ab73fd610a0ebaedc791f37dc2101e1ebe12d65c98b1c6f79c25af68e", compressed_public_key_st);
        }


        [Test]
        [Ignore("heavy")]
        public void HeavyTestComparison() {
            var r = new Random(DateTime.Now.Millisecond);
            var keyGen = new KeyGen();
            for(int i = 0; i < 10000; i++) {
                byte[] privateKeyBytes = new byte[32];
                r.NextBytes(privateKeyBytes);

                var hexPrivate = Convert.ToHexString(privateKeyBytes);

                var libResult = keyGen.GetPublicKey(privateKeyBytes);
                var nativeResult = keyGen.GetPublicKeyNative(privateKeyBytes);

                Assert.AreEqual(libResult, nativeResult, hexPrivate + "-" + i, null);
            }
        }


        [Test]
        [Ignore("heavy")]
        public void PefromanceWrapperSec256() {
            var r = new Random(DateTime.Now.Millisecond);
            var keyGen = new KeyGen();
            var watch = System.Diagnostics.Stopwatch.StartNew();
            for(int i = 0; i < 10000; i++) {

                if(i == 1000) {
                    watch.Restart();
                }
                byte[] privateKeyBytes = new byte[32];
                r.NextBytes(privateKeyBytes);

                // var hexPrivate = Convert.ToHexString(privateKeyBytes);

                var libResult = keyGen.GetPublicKey(privateKeyBytes);
                //var nativeResult = keyGen.GetPublicKeyNative(privateKeyBytes);


            }
            var elapsedMs = watch.ElapsedMilliseconds;
            Assert.Less(10, elapsedMs);
        }
        [Test]
        [Ignore("heavy")]
        public void PefromanceNativeSec256() {
            var r = new Random(DateTime.Now.Millisecond);
            var keyGen = new KeyGen();
            var watch = System.Diagnostics.Stopwatch.StartNew();
            for(int i = 0; i < 10000; i++) {

                if(i == 1000) {
                    watch.Restart();
                }
                byte[] privateKeyBytes = new byte[32];
                r.NextBytes(privateKeyBytes);

                // var hexPrivate = Convert.ToHexString(privateKeyBytes);

                //var libResult = keyGen.GetPublicKey(privateKeyBytes);
                var nativeResult = keyGen.GetPublicKeyNative(privateKeyBytes);


            }
            var elapsedMs = watch.ElapsedMilliseconds;
            Assert.Less(10, elapsedMs);
        }
        [Test]
        public void PlaingTestComparison() {
            var r = new Random(DateTime.Now.Millisecond);
            var keyGen = new KeyGen();
            // for(int i = 0; i < 10000; i++) {
            byte[] privateKeyBytes = new byte[32];

            privateKeyBytes = Convert.FromHexString("FF80A7C177E8C2444DEE3C2B5AAC6688761DDB49BCD03124F8B10541547C90EB");
            //r.NextBytes(privateKeyBytes);

            var hexPrivate = Convert.ToHexString(privateKeyBytes);

            var libResult = keyGen.GetPublicKey(privateKeyBytes);
            var nativeResult = keyGen.GetPublicKeyNative(privateKeyBytes);

            var libResultHex = Convert.ToHexString(libResult);
            var nativeResultHex = Convert.ToHexString(nativeResult);
            //025E75559CC1A98348FA5F6009843891FC4B83C74EACB727CC35B092D99B31738E
            Assert.AreEqual(libResultHex, nativeResultHex, hexPrivate, null);
            //}
        }
    }
}
