using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Nodes;

namespace Dag4.Net;

/// <summary>
/// Canonical JSON serializer producing deterministic output:
/// - Object properties sorted lexicographically
/// - Dictionaries serialized with sorted keys
/// - Arrays serialized in input order
/// - Null values removed from objects and dictionaries
/// Works with custom JsonConverters by first materializing a JsonNode and then
/// applying ordering and pruning on that DOM.
/// </summary>
public static class CanonicalJson
{
    private static readonly JsonSerializerOptions _options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = null,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never
        };
        return options;
    }

    /// <summary>
    /// Serialize value to UTF-8 bytes using the canonical settings.
    /// </summary>
    public static byte[] SerializeToBytes<T>(T value, JsonSerializerOptions? options = null)
    {
        var node = JsonSerializer.SerializeToNode(value, options ?? _options);
        var normalized = NormalizeNode(node);
        return System.Text.Encoding.UTF8.GetBytes(normalized?.ToJsonString() ?? "null");
    }
    /// <summary>
    /// Serialize value to a canonical JSON string.
    /// </summary>
    public static string SerializeToString<T>(T value, JsonSerializerOptions? options = null)
    {
        var node = JsonSerializer.SerializeToNode(value, options ?? _options);
        var normalized = NormalizeNode(node);
        return normalized?.ToJsonString() ?? "null";
    }

    /// <summary>
    /// Canonicalize an arbitrary JSON string by parsing into a JsonNode, sorting object properties
    /// lexicographically, and removing null values.
    /// </summary>
    public static string Canonicalize(string json)
    {
        var node = JsonNode.Parse(json);
        var normalized = NormalizeNode(node);
        return normalized?.ToJsonString() ?? "null";
    }

    /// <summary>
    /// Normalize a JsonNode in-place semantics by building new node instances with
    /// lexicographically sorted properties and no null values.
    /// </summary>
    internal static JsonNode? NormalizeNode(JsonNode? node)
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
