using System.Text.Json.Serialization;

namespace Dag4.Net;

// Minimal L0 currency AllowSpend model to share across apps
public class AllowSpendValue
{
    [JsonPropertyName("source")] public required string Source { get; init; }
    [JsonPropertyName("destination")] public required string Destination { get; init; }
    [JsonPropertyName("amount")] public required long Amount { get; init; }
    [JsonPropertyName("currencyId")] public string? CurrencyId { get; init; }
    [JsonPropertyName("lastValidEpochProgress")] public required long LastValidEpochProgress { get; init; }
    [JsonPropertyName("fee")] public long Fee { get; init; } = 0;
    [JsonPropertyName("approvers")] public required string[] Approvers { get; init; } = System.Array.Empty<string>();
    [JsonPropertyName("parent")] public required TransactionParent Parent { get; init; }
}

public class TransactionParent
{
    [JsonPropertyName("hash")] public required string Hash { get; init; }
    [JsonPropertyName("ordinal")] public required long Ordinal { get; init; }
}

public class TransactionProof
{
    [JsonPropertyName("id")] public required string Id { get; init; }
    [JsonPropertyName("signature")] public required string Signature { get; init; }
}

