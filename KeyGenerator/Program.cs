using KeyGenNameSpace;
using NBitcoin;
using NBitcoin.Secp256k1;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Diagnostics;
using System.Numerics;

namespace MyApp {
    internal class Program {
        static void Main(string[] args) {
            Console.WriteLine("Hello World!");
            var ctx = new Context();
            byte[] intBytes = BitConverter.GetBytes(3);
            byte[] inBt2 =new byte[32];

            //Array.Copy(intBytes, inBt2, intBytes.Length);

            //ReadOnlySpan<byte> privSpan = new ReadOnlySpan<byte>(inBt2);
            //var priv = ctx.CreateECPrivKey(privSpan);
            //var pub=ctx.g
            //var tst = new NBitcoin.Secp256k1.ECPrivKey();



            


            //var res = gen.GenerateFromString("test");

            //var privKey = res.PrivateKey; //9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
            //var wif = res.WIF; //"L2ZovMyTxxQVJmMtfQemgVcB5YmiEDapDwsvX6RqvuWibgUNRiHz"
            //var adr1 = res.Addresses[0]; //"19eA3hUfKRt7aZymavdQFXg5EZ6KCVKxr8"
            //var adr3 = res.Addresses[1]; //"3PEaV1m4nGi3yTKnzzmqjFTkxzrcFpier5"
            //var adrBc = res.Addresses[2]; //"bc1qtmrl9526rusw4dnavrcfal72tz6ram5lqzutru"

            var b = 3;
            //var r = new Random();
            //byte[] intBytes = BitConverter.GetBytes(1301);

            //var res = 1156 % 1000;
            //var res2 = 564 % 1000;

            ////var ts = KeyGen.GenerateFromString("cat");

            //var tInt = int.Parse("5749F", System.Globalization.NumberStyles.HexNumber);
            //BigInteger number65 = BigInteger.Multiply(Int64.MaxValue, 2);
            //BigInteger number66 = BigInteger.Multiply(number65, 2);

            //var diff=number66- number65;

            //var nn = number66.ToByteArray().Length;
            //Random random = new Random();
            //byte[] data = new byte[9];
            //random.NextBytes(data);
            //var cand= new BigInteger(data);

            //var biRes = number65 + cand % diff;


            var t1 = new Test();
            // t1.Test4(11, "1PgQVLmst3Z314JrQn5TNiys8Hc38TcXJu");
            // t1.Test4(17, "1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm");
            // t1.Test4(18, "1GnNTmTVLZiqQfLbAdp9DVdicEnB5GoERE");
            //t1.Test4(19, "1NWmZRpHH4XSPwsW6dsS3nrNWfL1yrJj4w");

            //  t1.TestBitInt(number65, number66, "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so");
            t1.Test6();
        }
    }

    public class Test {
        public void Test1() {

            var r = new Random(DateTime.Now.Millisecond);
            var k = new KeyGen();
            var watch = System.Diagnostics.Stopwatch.StartNew();
            for(int i = 0; i < 1000; i++) {
                byte[] bytes = new byte[32];
                r.NextBytes(bytes);
                var adrSet = k.GenerateFromBytes(bytes);
                if(i == 100) {
                    watch.Restart();
                }

            }
            var elapsedMs = watch.ElapsedMilliseconds;

            var t = TimeSpan.FromMilliseconds(watch.ElapsedMilliseconds);
            Console.WriteLine(t.ToString());
        }
        public void Test2() {

            // var r = new Random(DateTime.Now.Millisecond);
            var watch = System.Diagnostics.Stopwatch.StartNew();
            for(int i = 0; i < 10000; i++) {
                //   var st = r.Next().ToString();
                Key privateKey = new Key(); // generate a random private key
                PubKey publicKey = privateKey.PubKey;
                var adr1 = publicKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main);
                var adr2 = publicKey.GetAddress(ScriptPubKeyType.Segwit, Network.Main);
                var adr3 = publicKey.GetAddress(ScriptPubKeyType.SegwitP2SH, Network.Main);
                BitcoinSecret mainNetPrivateKey = privateKey.GetBitcoinSecret(Network.Main);  // generate our Bitcoin secret(also known as Wallet Import Format or simply WIF) from our private key for the mainnet
                var privateString = mainNetPrivateKey.ToString();
                var publicString = publicKey.ToString();
                if(i == 100) {
                    watch.Restart();
                }

            }
            var elapsedMs = watch.ElapsedMilliseconds;

            var t = TimeSpan.FromMilliseconds(watch.ElapsedMilliseconds);
            Console.WriteLine(t.ToString());
        }


        public void Test3() {
            var t1 = new Thread(GenerateKeys);
            t1.Name = "th1";
            var t2 = new Thread(GenerateKeys);
            t2.Name = "th2";

            t1.Start();
            Thread.Sleep(2000);
            t2.Start();
        }
        void GenerateKeys() {
            var k = new KeyGen();
            for(int i = 0; i < 1000; i++) {
                var adrSet = k.GenerateFromString(i.ToString());
                var val = adrSet.Addresses[1];
                Debug.Print(Thread.CurrentThread.Name + " " + val.ToString());
            }
        }


        public void Test4(int powMax, string target) {
            var powMin = powMax - 1;
            var min = Math.Pow(2, powMin);
            var max = Math.Pow(2, powMax);
            var len = max - min;
            var k = new KeyGen();
            int kk = 0;
            for(int i = (int)max; i >= min; i--) {
                kk++;
                if(kk % 10000 == 0) {
                    Console.Write("\r{0}/{1}", kk, len);
                }
                var adrSet = k.GenerateFromInt(i);
                if(adrSet.Addresses.Contains(target)) {
                    Console.WriteLine();
                    Console.WriteLine("found");
                    Console.WriteLine(adrSet.WIF);
                    Console.WriteLine(i);
                    var hx= i.ToString("X");
                    Console.WriteLine(hx);
                    Console.WriteLine();
                    Console.ReadLine();
                }
            }
            Console.WriteLine("finish");
        }

        public void Test6() {
            var r = new Random(DateTime.Now.Millisecond);
            BigInteger number65 = BigInteger.Multiply(Int64.MaxValue, 2);
            BigInteger number66 = BigInteger.Multiply(number65, 2);
            var diff = number66 - number65;
            byte[] bytes = new byte[9];
            while(true) {
                r.NextBytes(bytes);
                bytes[bytes.Length - 1] &= (byte)0x7F;
                var cand = new BigInteger(bytes);

                var biToCheck = number65 + cand % diff;
                if(biToCheck > number66) {
                    var t = 34;
                }
            }
        }

        public void TestBitInt(BigInteger min,BigInteger max, string target) {
          
            var len = max - min;
            var k = new KeyGen();
            int kk = 0;
            for(BigInteger i = max; i >= min; i--) {
                kk++;
                if(kk % 10000 == 0) {
                    Console.Write("\r{0}/{1}", kk, len);
                }
                var adrSet = k.GenerateFromBigInt(i);
                if(adrSet.Addresses.Contains(target)) {
                    Console.WriteLine();
                    Console.WriteLine("found");
                    Console.WriteLine(adrSet.WIF);
                    Console.WriteLine(i);
                    var hx = i.ToString("X");
                    Console.WriteLine(hx);
                    Console.WriteLine();
                    Console.ReadLine();
                }
            }
            Console.WriteLine("finish");
        }
    }
}