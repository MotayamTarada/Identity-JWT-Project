using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Text;

[ApiController]
[Route("api/[controller]")]

public class AuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IConfiguration _cfg;

    public AuthController(UserManager<IdentityUser> userManager, IConfiguration cfg)
    {
        _userManager = userManager;
        _cfg = cfg;
    }

    public record LoginDto(string Email, string Password);

    [HttpPost("token")]
    [AllowAnonymous]
    public async Task<IActionResult> Token(LoginDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user is null) return Unauthorized();

        if (!await _userManager.CheckPasswordAsync(user, dto.Password))
            return Unauthorized();

        var roles = await _userManager.GetRolesAsync(user);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName ?? user.Email!),
            new Claim(JwtRegisteredClaimNames.Email, user.Email!)
        };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_cfg["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _cfg["Jwt:Issuer"],
            audience: _cfg["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(int.Parse(_cfg["Jwt:ExpiresMinutes"] ?? "180")),
            signingCredentials: creds);

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);
        return Ok(new { access_token = jwt });
    }
}
