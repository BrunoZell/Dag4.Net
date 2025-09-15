using System.Text.Json;
using System.Text.Json.Serialization;
using System.Reflection;

namespace Dag4.Net;

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
        options.Converters.Add(new CanonicalObjectConverter());
        return options;
    }

    public static byte[] SerializeToBytes<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, _options);
    public static string SerializeToString<T>(T value) => JsonSerializer.Serialize(value, _options);

    private class CanonicalObjectConverter : JsonConverter<object>
    {
        public override bool CanConvert(Type typeToConvert)
        {
            return !typeToConvert.IsPrimitive && typeToConvert != typeof(string) && typeToConvert != typeof(DateTime) &&
                   typeToConvert != typeof(DateTimeOffset) && !typeToConvert.IsArray && !typeToConvert.IsEnum;
        }

        public override object Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            throw new NotSupportedException("Canonical encoder is write-only");

        public override void Write(Utf8JsonWriter writer, object value, JsonSerializerOptions options)
        {
            if (value == null) { writer.WriteNullValue(); return; }

            var type = value.GetType();
            if (value is System.Collections.IEnumerable enumerable && type != typeof(string))
            {
                writer.WriteStartArray();
                foreach (var item in enumerable)
                {
                    JsonSerializer.Serialize(writer, item, item?.GetType() ?? typeof(object), options);
                }
                writer.WriteEndArray();
                return;
            }

            writer.WriteStartObject();
            var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Where(p => p.CanRead)
                .OrderBy(p => GetPropertyName(p, options))
                .ToArray();

            foreach (var property in properties)
            {
                var propertyValue = property.GetValue(value);
                var propertyName = GetPropertyName(property, options);
                if (propertyValue != null || !ShouldIgnoreNull(property, options))
                {
                    writer.WritePropertyName(propertyName);
                    JsonSerializer.Serialize(writer, propertyValue, property.PropertyType, options);
                }
            }
            writer.WriteEndObject();
        }

        private static string GetPropertyName(PropertyInfo property, JsonSerializerOptions options)
        {
            var jsonPropertyName = property.GetCustomAttribute<JsonPropertyNameAttribute>();
            if (jsonPropertyName != null) return jsonPropertyName.Name;
            return options.PropertyNamingPolicy?.ConvertName(property.Name) ?? property.Name;
        }

        private static bool ShouldIgnoreNull(PropertyInfo property, JsonSerializerOptions options)
        {
            var ignoreAttribute = property.GetCustomAttribute<JsonIgnoreAttribute>();
            if (ignoreAttribute != null)
            {
                return ignoreAttribute.Condition == JsonIgnoreCondition.Always ||
                       ignoreAttribute.Condition == JsonIgnoreCondition.WhenWritingNull;
            }
            return options.DefaultIgnoreCondition == JsonIgnoreCondition.WhenWritingNull;
        }
    }
}

