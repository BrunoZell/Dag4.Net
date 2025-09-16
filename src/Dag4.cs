using System.Security.Cryptography;
using System.Text;

namespace Dag4.Net;

internal static class DagCrypto
{
    internal const string DataSignPrefix = "\u0019Constellation Signed Data:\n";

    /// <summary>
    /// Load secp256k1 ECDSA from 32-byte raw private key hex
    /// </summary>
    internal static ECDsa CreateSecp256k1FromPrivateKeyHex(string privateKeyHex)
    {
        ArgumentNullException.ThrowIfNull(privateKeyHex);
        byte[] d = Convert.FromHexString(privateKeyHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                                          ? privateKeyHex[2..] : privateKeyHex);
        if (d.Length != 32) throw new ArgumentException("Private key must be 32 bytes.");

        var curve = ECCurve.CreateFromFriendlyName("secP256k1");
        var ec = new ECParameters { Curve = curve, D = d };
        return ECDsa.Create(ec);
    }

    internal static ECDsa CreateSecp256k1FromPrivateKey(ReadOnlySpan<byte> privateKey32)
    {
        if (privateKey32.Length != 32) throw new ArgumentOutOfRangeException(nameof(privateKey32), "Private key must be 32 bytes.");
        var curve = ECCurve.CreateFromFriendlyName("secP256k1");
        var ec = new ECParameters { Curve = curve, D = privateKey32.ToArray() };
        return ECDsa.Create(ec);
    }

    internal static ECDsa CreateEcdsaFromPublicKey(PublicKey publicKey)
    {
        var xy = publicKey.AsBytes();
        var x = xy[..32].ToArray();
        var y = xy[32..].ToArray();
        return ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.CreateFromFriendlyName("secP256k1"),
            Q = new ECPoint { X = x, Y = y }
        });
    }

    internal static DerSignature SignData(ECDsa ecdsa, string jsonMessage)
    {
        ArgumentNullException.ThrowIfNull(ecdsa);
        ArgumentNullException.ThrowIfNull(jsonMessage);

        var normalizedJson = L0Json.Normalize(jsonMessage)?.ToJsonString() ?? "{}";
        var normalizedUtf8 = Encoding.UTF8.GetBytes(normalizedJson);
        var base64Message = Convert.ToBase64String(normalizedUtf8);
        var msg = DataSignPrefix + base64Message.Length.ToString() + "\n" + base64Message;
        var msgBytes = Encoding.UTF8.GetBytes(msg);

        var h256 = SHA256.HashData(msgBytes);
        var h256HexLower = Convert.ToHexString(h256).ToLowerInvariant();
        var h512 = SHA512.HashData(Encoding.UTF8.GetBytes(h256HexLower));

        var der = ecdsa.SignHash(h512, DSASignatureFormat.Rfc3279DerSequence);
        var derLowS = SigUtils.NormalizeDerToLowS(der);
        if (!ecdsa.VerifyHash(h512, derLowS, DSASignatureFormat.Rfc3279DerSequence))
            throw new InvalidOperationException("Local verify failed (data sign)");

        return DerSignature.FromBytes(derLowS);
    }

    internal static bool VerifyData(ECDsa ecdsa, string jsonMessage, DerSignature signature)
    {
        ArgumentNullException.ThrowIfNull(ecdsa);
        ArgumentNullException.ThrowIfNull(jsonMessage);

        var normalizedJson = L0Json.Normalize(jsonMessage)?.ToJsonString() ?? "{}";
        var normalizedUtf8 = Encoding.UTF8.GetBytes(normalizedJson);
        var base64Message = Convert.ToBase64String(normalizedUtf8);
        var msg = DataSignPrefix + base64Message.Length.ToString() + "\n" + base64Message;
        var h256 = SHA256.HashData(Encoding.UTF8.GetBytes(msg));
        var h512 = SHA512.HashData(Encoding.UTF8.GetBytes(Convert.ToHexString(h256).ToLowerInvariant()));
        return ecdsa.VerifyHash(h512, signature.AsBytes(), DSASignatureFormat.Rfc3279DerSequence);
    }

    /// <summary>
    /// Brotli-based signing for L0/L1 transactions (AllowSpend, etc.):
    /// canonical JSON (sorted) -> UTF8 -> Brotli(quality=2,window=22) -> sha256 -> hex(lower) -> sha512 -> ECDSA(secp256k1, DER low-S)
    /// Returns DER signature hex lowercase.
    /// </summary>
    internal static DerSignature SignL0(ECDsa ecdsa, string jsonMessage)
    {
        ArgumentNullException.ThrowIfNull(ecdsa);
        ArgumentNullException.ThrowIfNull(jsonMessage);

        var normalizedJson = L0Json.Normalize(jsonMessage)?.ToJsonString() ?? "{}";
        var normalizedUtf8 = Encoding.UTF8.GetBytes(normalizedJson);
        var compressed = BrotliCompress(normalizedUtf8);

        var h256Bytes = SHA256.HashData(compressed);
        var h256HexLower = Convert.ToHexString(h256Bytes).ToLowerInvariant();
        var h512 = SHA512.HashData(Encoding.UTF8.GetBytes(h256HexLower));

        var der = ecdsa.SignHash(h512, DSASignatureFormat.Rfc3279DerSequence);
        var derLowS = SigUtils.NormalizeDerToLowS(der);
        if (!ecdsa.VerifyHash(h512, derLowS, DSASignatureFormat.Rfc3279DerSequence))
            throw new InvalidOperationException("Local verify failed (l0 sign)");

        return DerSignature.FromBytes(derLowS);
    }

    /// <summary>
    /// Brotli compress with canonical parameters for Constellation validation
    /// </summary>
    internal static byte[] BrotliCompress(byte[] utf8Json)
    {
        ArgumentNullException.ThrowIfNull(utf8Json);
        using var encoder = new System.IO.Compression.BrotliEncoder(quality: 2, window: 22);
        var maxLen = System.IO.Compression.BrotliEncoder.GetMaxCompressedLength(utf8Json.Length);
        var dst = new byte[maxLen];
        encoder.Compress(utf8Json, dst, out var bytesConsumed, out var bytesWritten, isFinalBlock: true);
        if (bytesConsumed != utf8Json.Length)
            throw new InvalidOperationException("Brotli compression did not consume all input bytes");
        return dst[..bytesWritten];
    }
}
