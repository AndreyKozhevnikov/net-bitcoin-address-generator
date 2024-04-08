using NUnit.Framework;
using KeyGenNameSpace;
using Org.BouncyCastle.Math;
using System.Numerics;
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
        public void TestBigInt() {
            var val =  System.Numerics.BigInteger.Parse("30568377312064202855");
            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GenerateFromBigInt(val);
            Assert.AreEqual("18ZMbwUFLMHoZBbfpCjUJQTCMCbktshgpe", res.Addresses[0]);
        }


    }
}
