using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using QRCoder;
using Identity_JWT_Project.Helpers;
using System.IdentityModel.Tokens.Jwt;

namespace Identity_JWT_Project.Controllers
{
    public class ViewerController : Controller
    {
        private readonly IConfiguration _cfg;
        public ViewerController(IConfiguration cfg) => _cfg = cfg;

        // يرجّع PNG لرمز QR يحوي رابط /viewer?token=...
        [Authorize(Roles = "Admin")] // عدّل حسب حاجتك
        [HttpGet("/viewer/qr")]
        public IActionResult Qr()
        {
            var token = JwtHelper.CreateViewerJwt(_cfg);
            var url = $"{Request.Scheme}://{Request.Host}/viewer?token={token}";

            using var gen = new QRCodeGenerator();
            var data = gen.CreateQrCode(url, QRCodeGenerator.ECCLevel.Q);
            var png = new PngByteQRCode(data).GetGraphic(10);
            return File(png, "image/png");
        }
    }
}
