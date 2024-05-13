using NUnit.Framework;
using KeyGenNameSpace;
using Org.BouncyCastle.Math;
using System.Numerics;
using Newtonsoft.Json.Linq;
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
            var res =new KeyGen().GenerateFromString(input);

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
            var val =  System.Numerics.BigInteger.Parse("30568377312064202855");
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
        public void GetPublicKeyWithNative() {
            byte[] intBytes = BitConverter.GetBytes(3);
            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);


            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKeyNative(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", compressed_public_key_st);
        }

    }
}
