


using Secp256k1Net;
using SimpleBase;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace KeyGenNameSpace;
public class KeyGen {
    public AddressSet GenerateFromString(string value) {
        byte[] bytes = Encoding.ASCII.GetBytes(value);
        SHA256 mySHA256 = SHA256.Create();
        byte[] hashValue = mySHA256.ComputeHash(bytes);

        var st = BitConverter.ToString(hashValue);

        return GenerateFromBytes(hashValue);
    }
    public AddressSet GenerateFromBigInt(BigInteger value) {
        byte[] intBytes = value.ToByteArray();
        Array.Reverse(intBytes);
        byte[] res = new byte[32];
        var dest = 32 - intBytes.Length;
        Array.Copy(intBytes, 0, res, dest, intBytes.Length);
        return GenerateFromBytes(res);
    }
    public AddressSet GenerateFromInt(int value) {
        byte[] intBytes = BitConverter.GetBytes(value);
        Array.Reverse(intBytes);
        byte[] res = new byte[32];
        var dest = 32 - intBytes.Length;
        Array.Copy(intBytes, 0, res, dest, intBytes.Length);
        return GenerateFromBytes(res);

    }
    public KeyGen() {
        Initialize();
    }
    public void Initialize() {
        secp256k1 = new Secp256k1();
        mySHA256 = SHA256.Create();
    }



    SHA256 mySHA256;
    Secp256k1 secp256k1;

    public byte[] GetPublicKey(byte[] privateKey) {
        secp256k1.SecretKeyVerify(privateKey);

        // Derive public key bytes
        var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
        secp256k1.PublicKeyCreate(publicKey, privateKey);
        var publicKeySt = Convert.ToHexString(publicKey);

        // Serialize the public key to compressed format
        var compressed_public_key = new byte[Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH];
        secp256k1.PublicKeySerialize(compressed_public_key, publicKey, Flags.SECP256K1_EC_COMPRESSED);

        return compressed_public_key;
    }
    public byte[] GetPublicKeyNative(byte[] privateKey) {
        return MySec256.GetPublicKeyNative(privateKey);
    }



    public AddressSet GenerateFromBytes(byte[] bytes) {

        if(secp256k1 == null) {
            Initialize();
        }

        //private key
        var hexPrivate = Convert.ToHexString(bytes);
        var fullKey = "80" + hexPrivate + "01";

        //wif
        var checkSum = GetCheckSum(fullKey);
        var wifString = fullKey + checkSum;
        var wifBytes = Convert.FromHexString(wifString);
        string wif = Base58.Bitcoin.Encode(wifBytes);


        //public

        // Generate a private key
        var privateKey = bytes;

        var compressed_public_key = GetPublicKey(privateKey);
        var compressed_public_key_st = Convert.ToHexString(compressed_public_key).ToLower();
        //ripe160    
        var hasher = new Org.BouncyCastle.Crypto.Digests.RipeMD160Digest();
        var publSha = mySHA256.ComputeHash(compressed_public_key);
        hasher.BlockUpdate(publSha, 0, publSha.Length);
        var publicKeyHashByte = new byte[hasher.GetDigestSize()];
        hasher.DoFinal(publicKeyHashByte, 0);

        var public_key_hash_clean = Convert.ToHexString(publicKeyHashByte);


        var public_key_hash = "00" + public_key_hash_clean;


        //1adr

        checkSum = GetCheckSum(public_key_hash);
        wifString = public_key_hash + checkSum;
        wifBytes = Convert.FromHexString(wifString);
        string adr1 = Base58.Bitcoin.Encode(wifBytes);


        //3adr

        var redeem_script = "0014" + public_key_hash.Substring(2);
        var redeem_scriptBytes = Convert.FromHexString(redeem_script);
        var redeemSha256 = mySHA256.ComputeHash(redeem_scriptBytes);
        hasher.BlockUpdate(redeemSha256, 0, publSha.Length);
        var redeemRipe160 = new byte[hasher.GetDigestSize()];
        hasher.DoFinal(redeemRipe160, 0);
        var redeemRipe160St = Convert.ToHexString(redeemRipe160);
        var script_hash = "05" + redeemRipe160St;
        checkSum = GetCheckSum(script_hash);
        var adr3String = script_hash + checkSum;
        var adr3Bytes = Convert.FromHexString(adr3String);
        var adr3 = Base58.Bitcoin.Encode(adr3Bytes);


        //bc adr

        var witprog = Convert.FromHexString(public_key_hash_clean);
        // var ver = Convert.FromHexString("0x00");
        var adrBC = Bech32Converter.EncodeBech32(0, witprog, true, true);
        //var adrBC2 = Bech32Converter.EncodeBech32(0, witprog, false, true);



        var adr = new AddressSet();
        adr.PrivateKey = hexPrivate;
        adr.WIF = wif;
        adr.Addresses.Add(adr1);
        adr.Addresses.Add(adr3);
        adr.Addresses.Add(adrBC);
        return adr;
    }

    string GetCheckSum(string key) {
        var fullKeybytes = Convert.FromHexString(key);
        var sha1 = mySHA256.ComputeHash(fullKeybytes);
        var sha2 = mySHA256.ComputeHash(sha1);
        var sha2hex = Convert.ToHexString(sha2);
        var checkSum = sha2hex.Substring(0, 8);
        return checkSum;
    }
}
