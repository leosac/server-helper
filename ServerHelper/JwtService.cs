using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Leosac.ServerHelper
{
    public class JwtService : ITokenCreationService
    {
        private readonly JwtSettings _jwtSettings;

        public JwtService(IOptions<JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
        }

        public JwtService(JwtSettings jwtSettings)
        {
            _jwtSettings = jwtSettings;
        }

        public string CreateToken(string subjectId, IList<string>? roles = null, string? clientId = null)
        {
            return CreateToken(CreateClaims(subjectId, roles, clientId));
        }

        public string CreateToken(IEnumerable<Claim> claims, IList<string>? roles = null, string? clientId = null)
        {
            var expiration = DateTime.UtcNow.AddMinutes(_jwtSettings.Expiration);

            var token = CreateJwtToken(
                claims,
                CreateSigningCredentials(),
                expiration
            );

            var tokenHandler = new JwtSecurityTokenHandler();

            return tokenHandler.WriteToken(token);
        }

        private JwtSecurityToken CreateJwtToken(IEnumerable<Claim> claims, SigningCredentials credentials, DateTime expiration) =>
            new(
                _jwtSettings.Issuer,
                _jwtSettings.Audience,
                claims,
                expires: expiration,
                signingCredentials: credentials
            );

        public DateTime? GetExpirationDate(string token)
        {
            if (!string.IsNullOrEmpty(token))
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var t = tokenHandler.ReadToken(token);
                return t.ValidTo;
            }

            return null;
        }

        public Claim[] CreateBaseClaims()
        {
            return
            [
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
            ];
        }

        public Claim[] CreateClaims(string subjectId, IList<string>? roles = null, string? clientId = null)
        {
            var claims = new List<Claim>(CreateBaseClaims());
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, subjectId));
            if (roles != null)
            {
                foreach (var role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
            }
            if (!string.IsNullOrEmpty(clientId))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Azp, clientId));
            }
            return [.. claims];
        }

        private SigningCredentials CreateSigningCredentials()
        {
            var key = _jwtSettings.GetKey();

            return key == null
                ? throw new Exception("JWT Secret Key must be defined.")
                : new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256
            );
        }
    }
}
