
using Microsoft.AspNetCore.DataProtection.KeyManagement;

namespace Leosac.ServerHelper
{
    public class JwtSettings
    {
        static byte[]? ProcessLifetimeKey { get; set; }

        public string? Key { get; set; }

        public string? KeyFile { get; set; }

        public string? Issuer { get; set; }

        public string? Audience { get; set; }

        public int Expiration { get; set; } = 30;

        public bool IsEnabled()
        {
            return !string.IsNullOrEmpty(Key) || !string.IsNullOrEmpty(KeyFile);
        }

        public byte[]? GetKey(bool generateIfMissing = true)
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
            if (generateIfMissing)
            {
                if (ProcessLifetimeKey == null)
                {
                    // If no JWT key is defined, we generate one
                    // This will not be persistent, that means JWT tokens will be invalid after server reboot
                    // It is fine most of the time, and if not, the administrator should define a custom JWT key anyway
                    ProcessLifetimeKey = new byte[32];
                    Random.Shared.NextBytes(ProcessLifetimeKey);
                }
                return ProcessLifetimeKey;
            }
            return null;
        }
    }
}
