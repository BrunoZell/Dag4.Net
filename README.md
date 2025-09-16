# Dag4.Net - .NET SDK for Constellation (DAG)

This is he DAG .NET/C#/F# SDK for Constellation Network.

The Dag4.Net library provides secure wallet functionality and convenient wrappers for interacting with Constellation Network APIs. The library is platform agnostic and can be used to build apps on servers, desktop, smartphones, and browsers through WASM.


## Installation

Add the NuGet package `Dag4.Net`:

```
dotnet add package Dag4.Net
```

Or install it via the NuGet Package Manager Console:
```
Install-Package Dag4.Net
```

## Usage

### Create a key and address

```csharp
using Dag4.Net;

var wallet = DagAddress.FromPrivateKeyHex("0x<32-byte-hex>");
var dag = wallet.ToDagAddress();          // e.g., DAG1...
var publicKeyHex = wallet.ToPublicKeyHex(); // 64-byte X||Y hex (lowercase)
```

### Sign and verify data (dag4.js-style)
```csharp
var json = "{\"hello\":\"world\"}"; // any JSON string

// Signs normalized JSON (via L0Json) and returns key + DER signature
DagDataSignature signed = wallet.SignData(json);

// Verify (also normalizes JSON before hashing)
bool ok = wallet.VerifyData(json, signed.Signature.AsAsn1DerHex());
```

### Sign L0 payloads (Brotli path)
```csharp
var json = "{\"source\":\"...\",\"destination\":\"...\",\"amount\":1}";
DerSignature sig = wallet.SignL0(json);
var sigHex = sig.AsAsn1DerHex();
```

### Normalize arbitrary JSON for L0
```csharp
using System.Text.Json.Nodes;
using Dag4.Net;

var node = JsonNode.Parse(json);
var normalizedNode = L0Json.Normalize(node);         // JsonNode → JsonNode
var normalizedText = L0Json.NormalizeToString(json); // string → string
```

## Public API

- DagAddress
  - `static DagAddress FromPrivateKeyHex(string)`
  - `static DagAddress FromPublicKeyHex(string)`
  - `static DagAddress FromPublicKeyCoordinates(ReadOnlySpan<byte> x32, ReadOnlySpan<byte> y32)`
  - `string ToDagAddress()`
  - `string ToPublicKeyHex()`
  - `DagDataSignature SignData(string jsonMessage)`
  - `bool VerifyData(string jsonMessage, string signatureDerHex)`
  - `DerSignature SignL0(string jsonMessage)`

- Types
  - `PublicKey`: 64-byte X||Y (big-endian)
    - `ReadOnlySpan<byte> AsBytes()`
    - `string AsHex()`
  - `DerSignature`: ASN.1 DER-encoded ECDSA (R,S)
    - `ReadOnlySpan<byte> AsAsn1DerBytes()`
    - `string AsAsn1DerHex()`
  - `DagDataSignature`
    - `PublicKey PublicKey`
    - `DerSignature Signature`

- L0Json
  - `JsonNode? Normalize(JsonNode? node)`
  - `JsonNode? Normalize(string json)`
  - `string? NormalizeToString(JsonNode? node)`
  - `string? NormalizeToString(string json)`

## Notes

- Public key format is uncompressed 64-byte X||Y (lowercase hex when stringified).
- Signatures are ASN.1 DER; signatures produced by this library are normalized to low-S.
- JSON inputs are normalized (sorted object keys, nulls removed, array order preserved) before hashing.
- Kryo signing is not supported in this build.

## License

MIT License
