using System;
using System.Linq;
using System.Numerics;
using System.Text;

namespace Dag4.Net;

internal static class Base58
{
    private const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static readonly BigInteger Base = 58;

    public static string Encode(byte[] input)
    {
        if (input == null || input.Length == 0)
            return string.Empty;

        int leadingZeros = 0;
        for (int i = 0; i < input.Length; i++)
        {
            if (input[i] == 0) leadingZeros++; else break;
        }

        var num = new BigInteger(input.Reverse().Concat(new byte[] { 0 }).ToArray());
        var result = new StringBuilder();
        while (num > 0)
        {
            var remainder = (int)(num % Base);
            num /= Base;
            result.Insert(0, Alphabet[remainder]);
        }
        for (int i = 0; i < leadingZeros; i++) result.Insert(0, '1');
        return result.ToString();
    }

    public static byte[] Decode(string input)
    {
        if (string.IsNullOrEmpty(input)) return Array.Empty<byte>();

        int leadingOnes = 0;
        for (int i = 0; i < input.Length; i++)
        {
            if (input[i] == '1') leadingOnes++; else break;
        }

        BigInteger num = 0;
        for (int i = 0; i < input.Length; i++)
        {
            var charIndex = Alphabet.IndexOf(input[i]);
            if (charIndex < 0) throw new ArgumentException($"Invalid Base58 character: {input[i]}");
            num = num * Base + charIndex;
        }

        var bytes = num.ToByteArray();
        if (bytes.Length > 1 && bytes[bytes.Length - 1] == 0) bytes = bytes.Take(bytes.Length - 1).ToArray();
        Array.Reverse(bytes);

        var result = new byte[leadingOnes + bytes.Length];
        Array.Copy(bytes, 0, result, leadingOnes, bytes.Length);
        return result;
    }
}
