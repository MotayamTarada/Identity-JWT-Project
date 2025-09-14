

using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Identity_JWT_Project.Data;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity.UI.Services; // لو هتستخدم IEmailSender لاحقاً

var builder = WebApplication.CreateBuilder(args);

// ===== EF Core =====
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(opt => opt.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();
builder.Services.AddRazorPages(); // ضرورية لصفحات الهوية


// ===== Identity (كوكي مدمج) =====
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 7;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireDigit = false;
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddDefaultUI();


// ✅ Session dependencies
builder.Services.AddDistributedMemoryCache(); // لازم قبل AddSession
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(8);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});
// مسارات الكوكي الخاصة بالهوية (للتوجيه الصحيح)
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Identity/Account/Login";
    options.LogoutPath = "/Identity/Account/Logout";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
});

// ===== JWT (للـ API) بجانب الكوكي =====
var jwtKey = builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("Missing Jwt:Key");
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "IdentityJwtProject";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "IdentityJwtProject";



// مهم: لا تضف AddCookie مرة ثانية. خلي AddIdentity يتكفل بالكوكي.
// فقط أضف JWT كسكيما إضافي للـ API:
builder.Services.AddAuthentication()
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew = TimeSpan.Zero
        };
        options.SaveToken = true;
    });



builder.Services.AddAuthorization();
builder.Services.AddControllersWithViews();

var app = builder.Build();

// ===== Pipeline =====
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}
app.UseSession();          

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();


app.MapGet("/Account/Login", ctx =>
{
    ctx.Response.Redirect("/Identity/Account/Login" + (ctx.Request.QueryString.HasValue ? ctx.Request.QueryString.Value : ""));
    return Task.CompletedTask;
});
app.MapGet("/Account/Register", ctx =>
{
    ctx.Response.Redirect("/Identity/Account/Register" + (ctx.Request.QueryString.HasValue ? ctx.Request.QueryString.Value : ""));
    return Task.CompletedTask;
});

// MVC
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// صفحات Razor (الهوية)
app.MapRazorPages();

app.Run();

