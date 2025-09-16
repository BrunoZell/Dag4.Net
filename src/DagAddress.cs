using System.Security.Cryptography;

namespace Dag4.Net;

public sealed class DagAddress
{
    private readonly byte[]? _privateKey32; // present when constructed from private key
    private readonly PublicKey? _publicKey; // present when constructed from public key

    private DagAddress(byte[]? privateKey32, PublicKey? publicKey)
    {
        _privateKey32 = privateKey32;
        _publicKey = publicKey;
    }

    public static DagAddress FromPrivateKeyHex(string privateKeyHex)
    {
        ArgumentNullException.ThrowIfNull(privateKeyHex);
        var pk = Convert.FromHexString(privateKeyHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? privateKeyHex[2..] : privateKeyHex);
        if (pk.Length != 32) throw new ArgumentOutOfRangeException(nameof(privateKeyHex), "Private key must be 32 bytes.");
        return new DagAddress(pk, null);
    }

    public static DagAddress FromPublicKeyHex(string publicKeyHex)
    {
        ArgumentNullException.ThrowIfNull(publicKeyHex);
        var pub = PublicKey.FromHex(publicKeyHex);
        return new DagAddress(null, pub);
    }

    public static DagAddress FromPublicKeyCoordinates(ReadOnlySpan<byte> x32, ReadOnlySpan<byte> y32)
    {
        if (x32.Length != 32 || y32.Length != 32) throw new ArgumentOutOfRangeException("x32/y32", "X and Y must be 32 bytes each");
        var pub = PublicKey.FromCoordinates(x32, y32);
        return new DagAddress(null, pub);
    }

    public string ToPublicKeyHex()
    {
        if (_publicKey is PublicKey pk) return pk.AsHex();
        if (_privateKey32 is byte[] d)
        {
            using var ecdsa = DagCrypto.CreateSecp256k1FromPrivateKey(d);
            var parms = ecdsa.ExportParameters(false);
            var x = Pad32(parms.Q.X!);
            var y = Pad32(parms.Q.Y!);
            Span<byte> xy = stackalloc byte[64];
            x.CopyTo(xy.Slice(0, 32));
            y.CopyTo(xy.Slice(32, 32));
            return Convert.ToHexString(xy).ToLowerInvariant();
        }
        throw new InvalidOperationException("No key material present");
    }

    public string ToDagAddress()
    {
        PublicKey pk;
        if (_publicKey is PublicKey pub) pk = pub;
        else if (_privateKey32 is byte[] d)
        {
            using var ecdsa = DagCrypto.CreateSecp256k1FromPrivateKey(d);
            var p = ecdsa.ExportParameters(false);
            var x = Pad32(p.Q.X!);
            var y = Pad32(p.Q.Y!);
            pk = PublicKey.FromCoordinates(x, y);
        }
        else throw new InvalidOperationException("No key material present");

        var xy = pk.AsBytes();
        Span<byte> uncompressed65 = stackalloc byte[65];
        uncompressed65[0] = 0x04;
        xy[..32].CopyTo(uncompressed65.Slice(1, 32));
        xy[32..].CopyTo(uncompressed65.Slice(33, 32));

        var pubHex = Convert.ToHexString(uncompressed65).ToLowerInvariant();
        const string PkcsPrefix = "3056301006072a8648ce3d020106052b8104000a034200";
        var fullHex = PkcsPrefix + pubHex;
        var fullBytes = Convert.FromHexString(fullHex);
        var digest = SHA256.HashData(fullBytes);

        var b58 = Base58.Encode(digest);
        if (b58.Length < 36) throw new InvalidOperationException("Base58 too short");
        var hash36 = b58.Substring(b58.Length - 36, 36);
        var sum = hash36.Where(char.IsDigit).Sum(c => c - '0');
        var checkDigit = sum % 9;
        return $"DAG{checkDigit}{hash36}";
    }

    public DagDataSignature SignData(string jsonMessage)
    {
        ArgumentNullException.ThrowIfNull(jsonMessage);
        if (_privateKey32 is not byte[] d) throw new InvalidOperationException("This instance was not created with a private key");
        using var ecdsa = DagCrypto.CreateSecp256k1FromPrivateKey(d);
        var der = DagCrypto.SignData(ecdsa, jsonMessage);
        return new DagDataSignature(PublicKey.FromHex(ToPublicKeyHex()), der);
    }

    public bool VerifyData(string jsonMessage, string signatureDerHex)
    {
        ArgumentNullException.ThrowIfNull(jsonMessage);
        ArgumentNullException.ThrowIfNull(signatureDerHex);
        if (_publicKey is not PublicKey pk) throw new InvalidOperationException("This instance was not created with a public key");
        using var ecdsa = DagCrypto.CreateEcdsaFromPublicKey(pk);
        return DagCrypto.VerifyData(ecdsa, jsonMessage, DerSignature.FromHex(signatureDerHex));
    }

    public string SignL0(string canonicalJson)
    {
        ArgumentNullException.ThrowIfNull(canonicalJson);
        if (_privateKey32 is not byte[] d) throw new InvalidOperationException("This instance was not created with a private key");
        using var ecdsa = DagCrypto.CreateSecp256k1FromPrivateKey(d);
        return DagCrypto.SignL0(ecdsa, canonicalJson).AsHex();
    }

    private static byte[] Pad32(byte[] v)
    {
        if (v.Length == 32) return v;
        if (v.Length > 32) return v[^32..];
        var outp = new byte[32];
        Buffer.BlockCopy(v, 0, outp, 32 - v.Length, v.Length);
        return outp;
    }
}
