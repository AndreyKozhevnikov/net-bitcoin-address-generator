
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Math;
using Secp256k1Net;
using SimpleBase;
using System.IO;

using System.Security.Cryptography;
using System.Text;

namespace KeyGenNameSpace;
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
        var checkSum = sha2hex.Substring(0, 8);
        var wifString = fullKey + checkSum;
        var wifBytes = Convert.FromHexString(wifString);
        string wif = Base58.Bitcoin.Encode(wifBytes);


        //public
        using var secp256k1 = new Secp256k1();

        // Generate a private key
        var privateKey = bytes;

        secp256k1.SecretKeyVerify(privateKey);

        // Derive public key bytes
        var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
        var publ = secp256k1.PublicKeyCreate(publicKey, privateKey);

        // Serialize the public key to compressed format
        var serializedCompressedPublicKey = new byte[Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH];
        var publ2 = secp256k1.PublicKeySerialize(serializedCompressedPublicKey, publicKey, Flags.SECP256K1_EC_COMPRESSED);

        var x1 = Convert.ToHexString(publicKey);
        var x2 = Convert.ToHexString(serializedCompressedPublicKey);
        //BigInteger privKeyInt = new BigInteger(+1, bytes);
        //var parameters = SecNamedCurves.GetByName("secp256k1");
        //Org.BouncyCastle.Math.EC.ECPoint qa = parameters.G.Multiply(privKeyInt).Normalize();
        //Org.BouncyCastle.Math.EC.ECPoint qa2 = parameters.G.Multiply(privKeyInt);
        //var x1 = qa.AffineXCoord.ToBigInteger();
        //var y1 = qa.AffineYCoord.ToBigInteger();



        //var st2 = qa.GetEncoded();
        //var xBig = qa.XCoord.ToBigInteger();
        //var yBig = qa.YCoord.ToBigInteger();
        //byte[] pubKeyX = xBig.ToByteArrayUnsigned();
        //byte[] pubKeyY = yBig.ToByteArrayUnsigned();

        //var st1 = Convert.ToHexString(pubKeyX) + Convert.ToHexString(pubKeyY);
        //var parameters = SecNamedCurves.GetByName("secp256k1");
        //ECPoint qa = parameters.G.Multiply(privKeyInt);

        //byte[] pubKeyX = qa.X.ToBigInteger().ToByteArrayUnsigned();
        //byte[] pubKeyY = qa.Y.ToBigInteger().ToByteArrayUnsigned();

        //return Tuple.Create(pubKeyX, pubKeyY);


        var adr = new AddressSet();
        adr.PrivateKey = hexPrivate;
        adr.WIF = wif;
        return adr;
    }
}
