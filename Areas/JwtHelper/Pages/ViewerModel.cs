using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.IdentityModel.Tokens.Jwt;

namespace Identity_JWT_Project.Pages
{
    [Authorize(Policy = "ViewerOnly")] // لازم توكن Viewer صالح
    public class ViewerModel : PageModel
    {
        public int SecondsLeft { get; set; }
        public (int Users, int Roles, string LastSignInUtc) Metrics { get; set; }

        public void OnGet(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);
            SecondsLeft = (int)Math.Max(0, (jwt.ValidTo - DateTime.UtcNow).TotalSeconds);

            // بيانات تجريبية (بدّلها بقراءة من DB)
            Metrics = (Users: 1523, Roles: 7, LastSignInUtc: DateTime.UtcNow.AddMinutes(-12).ToString("u"));
        }
    }
}
