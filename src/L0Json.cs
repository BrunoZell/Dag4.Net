using System.Text.Json.Nodes;

namespace Dag4.Net;

/// <summary>
/// L0 JSON utilities for deterministic normalization and serialization.
/// - Normalize sorts object properties (ordinal), removes nulls, preserves array order.
/// - Works with custom JsonConverters by operating on System.Text.Json.Nodes.
/// </summary>
public static class L0Json
{
    // ------------------ Normalize (JsonNode / string) ------------------

    public static JsonNode? Normalize(JsonNode? node) => NormalizeNode(node);

    public static JsonNode? Normalize(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        var node = JsonNode.Parse(json);
        return NormalizeNode(node);
    }

    public static string? NormalizeToString(JsonNode? node) => Normalize(node)?.ToJsonString();
    public static string? NormalizeToString(string json) => Normalize(json)?.ToJsonString();

    // ------------------ Internals ------------------

    private static JsonNode? NormalizeNode(JsonNode? node)
    {
        if (node is null || node is JsonValue) return node;
        if (node is JsonArray arr)
        {
            var outArr = new JsonArray();
            foreach (var item in arr)
            {
                var norm = NormalizeNode(item);
                if (norm is not null) outArr.Add(norm);
            }
            return outArr;
        }
        if (node is JsonObject obj)
        {
            var keys = new List<string>();
            foreach (var kv in obj) keys.Add(kv.Key);
            keys.Sort(StringComparer.Ordinal);
            var outObj = new JsonObject();
            foreach (var k in keys)
            {
                var v = obj[k];
                var norm = NormalizeNode(v);
                if (norm is not null) outObj[k] = norm;
            }
            return outObj;
        }
        return node;
    }
}
