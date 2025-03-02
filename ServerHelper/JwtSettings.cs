
namespace Leosac.ServerHelper
{
    public class JwtSettings
    {
        public string? Key { get; set; }

        public string? KeyFile { get; set; }

        public string? Issuer { get; set; }

        public string? Audience { get; set; }

        public int Expiration { get; set; } = 30;

        public byte[]? GetKey()
        {
            var key = Key;
            if (string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(KeyFile))
            {
                key = File.ReadAllText(KeyFile);
            }
            if (!string.IsNullOrEmpty(key))
            {
                return System.Text.Encoding.UTF8.GetBytes(key);
            }
            return null;
        }
    }
}
