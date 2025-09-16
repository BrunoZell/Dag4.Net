using System.Formats.Asn1;
using System.Numerics;

namespace Dag4.Net;

internal static class SigUtils
{
    private static readonly BigInteger N = BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    private static readonly BigInteger HalfN = N >> 1;

    public static byte[] NormalizeDerToLowS(ReadOnlyMemory<byte> derSignature)
    {
        var reader = new AsnReader(derSignature, AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        var r = seq.ReadIntegerBytes().ToArray();
        var s = seq.ReadIntegerBytes().ToArray();
        seq.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();

        var rPos = ToUnsignedBigEndian(r);
        var sPos = ToUnsignedBigEndian(s);

        var sVal = new BigInteger(AddLeadingZeroIfNeeded(sPos), isUnsigned: true, isBigEndian: true);
        if (sVal > HalfN)
        {
            var sNorm = N - sVal;
            sPos = ToMinimalUnsignedBigEndian(sNorm);
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        WriteDerInteger(writer, rPos);
        WriteDerInteger(writer, sPos);
        writer.PopSequence();
        return writer.Encode();
    }

    public static bool IsLowS(ReadOnlyMemory<byte> derSignature)
    {
        var reader = new AsnReader(derSignature, AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        _ = seq.ReadIntegerBytes();
        var s = seq.ReadIntegerBytes().ToArray();
        seq.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();

        var sPos = ToUnsignedBigEndian(s);
        var sVal = new BigInteger(AddLeadingZeroIfNeeded(sPos), isUnsigned: true, isBigEndian: true);
        return sVal <= HalfN;
    }

    private static BigInteger BigInt(string hex) =>
        new BigInteger(AddLeadingZeroIfNeeded(Convert.FromHexString(hex)), isUnsigned: true, isBigEndian: true);

    private static byte[] ToUnsignedBigEndian(byte[] twoComp)
    {
        if (twoComp.Length == 0) return twoComp;
        if (twoComp[0] == 0x00)
        {
            int i = 1; while (i < twoComp.Length && twoComp[i] == 0x00) i++;
            return twoComp.AsSpan(i).ToArray();
        }
        return twoComp;
    }

    private static byte[] AddLeadingZeroIfNeeded(byte[] be) =>
        (be.Length > 0 && (be[0] & 0x80) != 0) ? (new byte[] { 0x00 }).Concat(be).ToArray() : be;

    private static byte[] ToMinimalUnsignedBigEndian(BigInteger v)
    {
        var tmp = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        int i = 0; while (i < tmp.Length - 1 && tmp[i] == 0x00) i++;
        return tmp.AsSpan(i).ToArray();
    }

    private static void WriteDerInteger(AsnWriter w, byte[] unsigned)
    {
        var pos = AddLeadingZeroIfNeeded(unsigned);
        w.WriteInteger(pos);
    }
}
