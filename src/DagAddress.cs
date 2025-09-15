using System.Security.Cryptography;

namespace Dag4.Net;

public sealed class DagAddress
{
    private readonly ECDsa _ecdsa;

    private DagAddress(ECDsa ecdsa)
    {
        _ecdsa = ecdsa ?? throw new ArgumentNullException(nameof(ecdsa));
    }

    public static DagAddress FromPrivateKeyHex(string hexPriv32)
    {
        var ecdsa = DagCrypto.CreateSecp256k1FromPrivateKeyHex(hexPriv32);
        return new DagAddress(ecdsa);
    }

    public static DagAddress FromPublicKeyHex(string proofIdHex)
    {
        var ecdsa = DagCrypto.CreateEcdsaFromProofIdHex(proofIdHex);
        return new DagAddress(ecdsa);
    }

    public string ToProofIdHex()
    {
        var p = _ecdsa.ExportParameters(false);
        var x = Pad32(p.Q.X!);
        var y = Pad32(p.Q.Y!);
        Span<byte> xy = stackalloc byte[64];
        x.CopyTo(xy.Slice(0, 32));
        y.CopyTo(xy.Slice(32, 32));
        return Convert.ToHexString(xy.ToArray()).ToLowerInvariant();
    }

    public string ToDagAddress()
    {
        var p = _ecdsa.ExportParameters(false);
        var x = Pad32(p.Q.X!);
        var y = Pad32(p.Q.Y!);

        Span<byte> uncompressed65 = stackalloc byte[65];
        uncompressed65[0] = 0x04;
        x.CopyTo(uncompressed65.Slice(1, 32));
        y.CopyTo(uncompressed65.Slice(33, 32));

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
        var derHex = DagCrypto.SignDataDerHex(_ecdsa, jsonMessage);
        return new DagDataSignature(ToProofIdHex(), derHex);
    }

    public bool VerifyData(string jsonMessage, string signatureDerHex)
    {
        return DagCrypto.VerifyData(_ecdsa, jsonMessage, signatureDerHex);
    }

    public string SignL0(string canonicalJson)
    {
        return DagCrypto.SignL0(_ecdsa, canonicalJson);
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

