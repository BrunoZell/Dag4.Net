using System.Diagnostics;
using System.Formats.Asn1;

namespace Dag4.Net;

/// <summary>
/// Result of signing a message or canonical JSON: includes the associated public key
/// (64-byte X||Y) and the ECDSA DER signature normalized to low-S.
/// </summary>
public readonly record struct DagDataSignature
{
    /// <summary>
    /// Initialize a new result with the provided public key and signature.
    /// </summary>
    public DagDataSignature(PublicKey publicKey, DerSignature signature)
    {
        PublicKey = publicKey;
        Signature = signature;
    }

    /// <summary>The uncompressed secp256k1 public key in 64-byte X||Y form.</summary>
    public PublicKey PublicKey { get; }
    /// <summary>DER-encoded ECDSA signature (R,S) normalized to low-S.</summary>
    public DerSignature Signature { get; }
}

/// <summary>
/// Represents a secp256k1 public key in 64-byte X||Y big-endian form.
/// Provides construction helpers and hex/bytes accessors.
/// </summary>
public readonly struct PublicKey
{
    private readonly byte[] _xy; // 64 bytes X||Y

    private PublicKey(byte[] xy)
    {
        _xy = xy;
    }

    /// <summary>
    /// Create a public key from a 64-byte hex string (X||Y), case-insensitive.
    /// </summary>
    public static PublicKey FromHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        var bytes = Convert.FromHexString(hex);
        if (bytes.Length != 64) throw new ArgumentOutOfRangeException(nameof(hex), "Public key must be 64 bytes (X||Y)");
        return new PublicKey(bytes);
    }

    /// <summary>
    /// Create a public key from two 32-byte big-endian coordinates X and Y.
    /// </summary>
    public static PublicKey FromCoordinates(ReadOnlySpan<byte> x32, ReadOnlySpan<byte> y32)
    {
        if (x32.Length != 32 || y32.Length != 32) throw new ArgumentOutOfRangeException("x32/y32", "X and Y must be 32 bytes each");
        var xy = new byte[64];
        x32.CopyTo(xy.AsSpan(0, 32));
        y32.CopyTo(xy.AsSpan(32, 32));
        return new PublicKey(xy);
    }

    /// <summary>
    /// Returns the 64-byte X||Y representation as a read-only span (no copy).
    /// </summary>
    public ReadOnlySpan<byte> AsBytes() => _xy;
    /// <summary>
    /// Returns the lower-cased hex encoding of the 64-byte X||Y representation.
    /// </summary>
    public string AsHex() => Convert.ToHexString(_xy).ToLowerInvariant();
}

/// <summary>
/// Represents a DER-encoded ECDSA signature (R,S) normalized to low-S, with
/// helpers to construct from hex/bytes and retrieve hex/bytes.
/// </summary>
public readonly struct DerSignature
{
    private readonly byte[] _der;

    private DerSignature(byte[] der)
    {
        _der = der;
    }

    /// <summary>
    /// Create a DER signature from a hex string, case-insensitive.
    /// Validates ASN.1 DER SEQUENCE of two INTEGERs; throws FormatException if invalid.
    /// </summary>
    internal static DerSignature FromHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        var bytes = Convert.FromHexString(hex);
        if (!TryValidateDer(bytes)) throw new FormatException("Invalid ECDSA DER signature.");
        return new DerSignature(bytes);
    }

    /// <summary>
    /// Create a DER signature from raw bytes. A defensive copy is taken.
    /// In DEBUG builds, asserts that input is a valid ECDSA DER signature.
    /// </summary>
    internal static DerSignature FromBytes(ReadOnlySpan<byte> der)
    {
#if DEBUG
        Debug.Assert(TryValidateDer(der), "Invalid ECDSA DER signature passed to DerSignature.FromBytes");
#endif
        var b = der.ToArray();
        return new DerSignature(b);
    }

    /// <summary>
    /// Returns raw DER bytes as a read-only span (no copy).
    /// </summary>
    public ReadOnlySpan<byte> AsAsn1DerBytes() => _der;

    /// <summary>
    /// Returns the lower-cased hex encoding of the DER signature.
    /// </summary>
    public string AsAsn1DerHex() => Convert.ToHexString(_der).ToLowerInvariant();

    private static bool TryValidateDer(ReadOnlySpan<byte> der)
    {
        try
        {
            var reader = new AsnReader(der.ToArray(), AsnEncodingRules.DER);
            var seq = reader.ReadSequence();
            // R
            var r = seq.ReadIntegerBytes();
            if (r.Span.Length == 0) return false;
            // S
            var s = seq.ReadIntegerBytes();
            if (s.Span.Length == 0) return false;
            seq.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            return true;
        }
        catch
        {
            return false;
        }
    }
}
