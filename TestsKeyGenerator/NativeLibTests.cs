using KeyGenNameSpace;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestsKeyGenerator {
    [TestFixture]
    public class NativeLibTests {
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
        public void GetPublicKeyWithNative_1() {
            byte[] intBytes = BitConverter.GetBytes(11);


            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);

            //Array.Reverse(privateKeyBytes);
            //var tst = BitConverter.ToInt32(privateKeyBytes, 0);

            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKeyNative(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithNative_2() {
            byte[] intBytes = BitConverter.GetBytes(3464879846);


            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);

            //Array.Reverse(privateKeyBytes);
            //var tst = BitConverter.ToInt32(privateKeyBytes, 0);

            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKeyNative(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("0222c6cde840c26dab252ce847e81bfa3fe7fa59c5cfb5879337a0e6117205837b", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithNative_3() {
            byte[] intBytes = BitConverter.GetBytes(1234);


            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);

            //Array.Reverse(privateKeyBytes);
            //var tst = BitConverter.ToInt32(privateKeyBytes, 0);

            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKeyNative(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("02e37648435c60dcd181b3d41d50857ba5b5abebe279429aa76558f6653f1658f2", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithNative_4() {
            byte[] intBytes = BitConverter.GetBytes(235);


            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);

            //Array.Reverse(privateKeyBytes);
            //var tst = BitConverter.ToInt32(privateKeyBytes, 0);

            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKeyNative(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("02d5e9e1da649d97d89e4868117a465a3a4f8a18de57a140d36b3f2af341a21b52", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithNative_5() {
            byte[] intBytes = BitConverter.GetBytes(56);


            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);

            //Array.Reverse(privateKeyBytes);
            //var tst = BitConverter.ToInt32(privateKeyBytes, 0);

            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKeyNative(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("02bce74de6d5f98dc027740c2bbff05b6aafe5fd8d103f827e48894a2bd3460117", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithNative_6() {
            byte[] intBytes = BitConverter.GetBytes(123);


            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);

            //Array.Reverse(privateKeyBytes);
            //var tst = BitConverter.ToInt32(privateKeyBytes, 0);

            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKeyNative(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithNative_7() {
            byte[] intBytes = BitConverter.GetBytes(2125123);


            Array.Reverse(intBytes);
            byte[] privateKeyBytes = new byte[32];
            var dest = 32 - intBytes.Length;
            Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);

            //Array.Reverse(privateKeyBytes);
            //var tst = BitConverter.ToInt32(privateKeyBytes, 0);

            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKeyNative(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("039840c46ab73fd610a0ebaedc791f37dc2101e1ebe12d65c98b1c6f79c25af68e", compressed_public_key_st);
        }


        [Test]
        public void GetPublicKeyWithNative_8() {
            byte[] privateKeyBytes = Convert.FromHexString("FF80A7C177E8C2444DEE3C2B5AAC6688761DDB49BCD03124F8B10541547C90EB");


            //Array.Reverse(intBytes);
            //byte[] privateKeyBytes = new byte[32];
            //var dest = 32 - intBytes.Length;
            //Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);

            //Array.Reverse(privateKeyBytes);
            //var tst = BitConverter.ToInt32(privateKeyBytes, 0);

            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKeyNative(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("025e75559cc1a98348fa5f6009843891fc4b83c74eacb727cc35b092d99b31738e", compressed_public_key_st);
        }
        [Test]
        public void GetPublicKeyWithNative_9() {
            byte[] privateKeyBytes = Convert.FromHexString("D3633F2569C83366B5AE8C84CD76B2B493600D60A23157B98495C48CCC916BB3");


            //Array.Reverse(intBytes);
            //byte[] privateKeyBytes = new byte[32];
            //var dest = 32 - intBytes.Length;
            //Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);

            //Array.Reverse(privateKeyBytes);
            //var tst = BitConverter.ToInt32(privateKeyBytes, 0);

            //BigInteger number66 = BigInteger.Multiply(number65, 2);
            var res = new KeyGen().GetPublicKeyNative(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();


            Assert.AreEqual("02002a8822e098d76dcc237031c5590a8ea7cd4ce0fe6e3b4213e47770e9befda8", compressed_public_key_st);
        }
        
    }
}
