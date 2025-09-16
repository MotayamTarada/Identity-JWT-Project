


using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Identity_JWT_Project.Data;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity.UI.Services; // (optional) if you'll use IEmailSender later

var builder = WebApplication.CreateBuilder(args);

// ===== EF Core =====
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(opt => opt.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddRazorPages(); // needed for Identity UI pages
builder.Services.AddControllersWithViews();

// ===== Identity (cookie-based) =====
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

// ===== Session =====
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(8);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Identity cookie paths
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Identity/Account/Login";
    options.LogoutPath = "/Identity/Account/Logout";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
});

// ===== JWT (API) + Viewer QR JWT (query on /viewer) =====
var jwtKey = builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("Missing Jwt:Key");
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "IdentityJwtProject";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "IdentityJwtProject";
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));


builder.Services.AddAuthentication()
    // API bearer
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = signingKey,
            ClockSkew = TimeSpan.Zero
        };
        options.SaveToken = true;
    })
    // Viewer QR bearer (query token)
    .AddJwtBearer("ViewerScheme", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = signingKey,
            ClockSkew = TimeSpan.FromSeconds(10)
        };

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var token = context.Request.Query["token"];
                if (!string.IsNullOrEmpty(token) &&
                    context.Request.Path.StartsWithSegments("/viewer", StringComparison.OrdinalIgnoreCase))
                {
                    context.Token = token;
                }
                return Task.CompletedTask;
            }
        };
    });

// Authorization (add ViewerOnly policy)
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ViewerOnly", policy =>
        policy.AddAuthenticationSchemes("ViewerScheme")
              .RequireAuthenticatedUser()
              .RequireRole("Viewer"));
});

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

// Convenience redirects for /Account/* to Identity UI
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

// MVC + Razor Pages
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

app.Run();
