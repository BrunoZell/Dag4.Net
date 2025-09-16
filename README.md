# Dag4.Net - .NET SDK for Constellation (DAG)

Slim primitives to derive DAG addresses and sign payloads in .NET.

## Installation

Add the project/package and import `Dag4.Net`.

## Usage

### Create a key and address
```csharp
using Dag4.Net;

var wallet = DagAddress.FromPrivateKeyHex("0x<32-byte-hex>");
var dag = wallet.ToDagAddress();      // e.g., DAG1...
var proof = wallet.ToProofIdHex();    // 64-byte X||Y hex
```

### Sign and verify data
```csharp
var msg = "{\"hello\":\"world\"}";
var sig = wallet.SignData(msg);       // returns DagDataSignature
var ok = wallet.VerifyData(msg, sig.SignatureDerHex);
```

### Sign L0 payloads (Brotli path)
```csharp
var value = new { source = "...", destination = "...", amount = 1L };
var canonical = CanonicalJson.SerializeToString(value);
var signatureHex = wallet.SignL0(canonical);
```

## API

- `DagAddress.FromPrivateKeyHex(string)` → `DagAddress`
- `DagAddress.FromPublicKeyHex(string proofIdHex)` → `DagAddress`
- `DagAddress.ToDagAddress()` → `string`
- `DagAddress.ToProofIdHex()` → `string`
- `DagAddress.SignData(string jsonMessage)` → `DagDataSignature`
- `DagAddress.VerifyData(string jsonMessage, string signatureDerHex)` → `bool`
- `DagAddress.SignL0(string canonicalJson)` → `string` (DER hex)
- `CanonicalJson.SerializeToString<T>(T)` / `SerializeToBytes<T>(T)`

Notes:
- Input to `SignL0` must be canonical JSON.
- Kryo signing is not supported in this build.

## License

MIT License
