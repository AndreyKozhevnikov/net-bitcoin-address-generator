using Nethereum.Signer;
using Nethereum.Signer.Crypto;
using SimpleBase;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace KeyGenNameSpace {
    public class KeyGen {
        public static AddressSet GenerateFromString(string value) {
            byte[] bytes = Encoding.ASCII.GetBytes(value);
            SHA256 mySHA256 = SHA256.Create();
            byte[] hashValue = mySHA256.ComputeHash(bytes);

            var st = BitConverter.ToString(hashValue);

            return GenerateFromBytes(hashValue);
        }
        public static AddressSet GenerateFromBytes(byte[] bytes) {
            //private key
            var hexPrivate = Convert.ToHexString(bytes);
            var fullKey = "80" + hexPrivate + "01";
            SHA256 mySHA256 = SHA256.Create();
            byte[] fullKeybytes = Convert.FromHexString(fullKey);
            var sha1 = mySHA256.ComputeHash(fullKeybytes);
            var sha2 = mySHA256.ComputeHash(sha1);
            var sha2hex = Convert.ToHexString(sha2);

            //wif
            var checkSum = sha2hex.Substring(0,8);
            var wifString = fullKey + checkSum;
            var wifBytes=Convert.FromHexString(wifString);
            string wif = Base58.Bitcoin.Encode(wifBytes);


            var adr = new AddressSet();
            adr.PrivateKey = hexPrivate;
            adr.WIF = wif;
            return adr;
        }
    }
}
