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

            //Array.Reverse(privateKeyBytes);
            //var tst = BitConverter.ToInt32(privateKeyBytes, 0);

            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKeyNative(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", compressed_public_key_st);
        }

        [Test]
        public void ModInverse() {
            BigInteger input1 = BigInteger.Parse("65341020041517633956166170261014086368942546761318486551877808671514674964848");
            BigInteger input2 = BigInteger.Parse("115792089237316195423570985008687907853269984665640564039457584007908834671663");
            BigInteger target = BigInteger.Parse("83174505189910067536517124096019359197644205712500122884473429251812128958118");

            var result = MySec256.modInverse(input1, input2);

            Assert.AreEqual(target, result);
        }

        [Test]
        public void MyModulus() {
            BigInteger input1 = BigInteger.Parse("756628490253123014067933708583503295844929075882239485540431356534910033618830501144105195285364489562157441837796863614070956636498456792910898817389940831543204657474297072356228690296487944931559885281889207062770782744748470400");
            BigInteger input2 = BigInteger.Parse("115792089237316195423570985008687907853269984665640564039457584007908834671663");
            BigInteger target = BigInteger.Parse("91914383230618135761690975197207778399550061809281766160147273830617914855857");

            var result = MySec256.MyModulus(input1, input2);

            Assert.AreEqual(target, result);
        }
        [Test]
        public void Double() {
            BigInteger input1 = BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240");
            BigInteger input2 = BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424");
            var point = new Tuple<BigInteger, BigInteger>(input1, input2);
            BigInteger target1 = BigInteger.Parse("89565891926547004231252920425935692360644145829622209833684329913297188986597");
            BigInteger target2 = BigInteger.Parse("12158399299693830322967808612713398636155367887041628176798871954788371653930");

            var targetPoint= new Tuple<BigInteger, BigInteger>(target1, target2);
            var result = MySec256.Double(point);

            Assert.AreEqual(targetPoint, result);
        }


    }
}
