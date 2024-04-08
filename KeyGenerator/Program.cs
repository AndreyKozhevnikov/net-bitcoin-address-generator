using KeyGenNameSpace;
using NBitcoin;
using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;

namespace MyApp {
    internal class Program {
        static void Main(string[] args) {
            Console.WriteLine("Hello World!");

            //var ts = KeyGen.GenerateFromString("cat");
            //var ts2 = KeyGen.GenerateFromString("test");
            var tInt = int.Parse("5749F", System.Globalization.NumberStyles.HexNumber);

            var t1 = new Test();
            // t1.Test4(11, "1PgQVLmst3Z314JrQn5TNiys8Hc38TcXJu");
            // t1.Test4(17, "1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm");
            // t1.Test4(18, "1GnNTmTVLZiqQfLbAdp9DVdicEnB5GoERE");
            //t1.Test4(19, "1NWmZRpHH4XSPwsW6dsS3nrNWfL1yrJj4w");


            System.Numerics.BigInteger number65 = System.Numerics.BigInteger.Multiply(Int64.MaxValue, 2);
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
    }
}