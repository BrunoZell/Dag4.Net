namespace Dag4.Net;

public readonly record struct DagDataSignature(PublicKey PublicKey, DerSignature Signature);

public readonly struct PublicKey
{
    private readonly byte[] _xy; // 64 bytes X||Y

    private PublicKey(byte[] xy)
    {
        _xy = xy;
    }

    public static PublicKey FromHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        var bytes = Convert.FromHexString(hex);
        if (bytes.Length != 64) throw new ArgumentOutOfRangeException(nameof(hex), "Public key must be 64 bytes (X||Y)");
        return new PublicKey(bytes);
    }

    public static PublicKey FromCoordinates(ReadOnlySpan<byte> x32, ReadOnlySpan<byte> y32)
    {
        if (x32.Length != 32 || y32.Length != 32) throw new ArgumentOutOfRangeException("x32/y32", "X and Y must be 32 bytes each");
        var xy = new byte[64];
        x32.CopyTo(xy.AsSpan(0, 32));
        y32.CopyTo(xy.AsSpan(32, 32));
        return new PublicKey(xy);
    }

    public ReadOnlySpan<byte> AsBytes() => _xy;
    public string AsHex() => Convert.ToHexString(_xy).ToLowerInvariant();
}

public readonly struct DerSignature
{
    private readonly byte[] _der;

    private DerSignature(byte[] der)
    {
        _der = der;
    }

    public static DerSignature FromHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        var bytes = Convert.FromHexString(hex);
        return new DerSignature(bytes);
    }

    public static DerSignature FromBytes(ReadOnlySpan<byte> der)
    {
        var b = der.ToArray();
        return new DerSignature(b);
    }

    public ReadOnlySpan<byte> AsBytes() => _der;
    public string AsHex() => Convert.ToHexString(_der).ToLowerInvariant();
}
