using System.Security.Claims;

namespace Leosac.ServerHelper
{
    public interface ITokenCreationService
    {
        string CreateToken(string subjectId, IList<string>? roles = null, string? clientId = null);

        string CreateToken(IEnumerable<Claim> claims, IList<string>? roles = null, string? clientId = null);

        DateTime? GetExpirationDate(string token);

        Claim[] CreateClaims(string subjectId, IList<string>? roles = null, string? clientId = null);
    }
}
