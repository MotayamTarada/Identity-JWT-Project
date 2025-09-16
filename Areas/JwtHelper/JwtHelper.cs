using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Identity_JWT_Project.Helpers
{
    public static class JwtHelper
    {
        public static string CreateViewerJwt(IConfiguration cfg)
        {
            var key = cfg["Jwt:Key"]!;
            var issuer = cfg["Jwt:Issuer"]!;
            var audience = cfg["Jwt:Audience"]!;
            var minutes = int.TryParse(cfg["Jwt:Minutes"], out var m) ? m : 15;

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "guest"),
                new Claim(ClaimTypes.Role, "Viewer")
            };

            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var creds = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer, audience, claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(minutes),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
