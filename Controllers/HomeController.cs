

using Identity_JWT_Project.Data;
using Identity_JWT_Project.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

[Authorize]
public class HomeController : Controller
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<IdentityUser> _userManager;

    public HomeController(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
    {
        _roleManager = roleManager;
        _userManager = userManager;
    }



    // GET: /Roles
    [HttpGet]
    public IActionResult Index()
    {
        var roles = _roleManager.Roles
            .Select(r => new RoleVm { RoleId = r.Id, RoleName = r.Name! })
            .ToList();
        return View(roles);
    }

    // GET: /Roles/Create
    [HttpGet]
    public IActionResult Create() => View(new RoleVm());

    // POST: /Roles/Create
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(RoleVm model)
    {
        //if (!ModelState.IsValid) return View(model);

        var exists = await _roleManager.RoleExistsAsync(model.RoleName);
        if (exists)
        {
            ModelState.AddModelError(nameof(model.RoleName), "Role already exists.");
            return View(model);
        }

        var result = await _roleManager.CreateAsync(new IdentityRole(model.RoleName));
        if (!result.Succeeded)
        {
            foreach (var e in result.Errors) ModelState.AddModelError("", e.Description);
            return View(model);
        }

        TempData["Success"] = "Role created.";
        return RedirectToAction(nameof(Index));
    }

    // GET: /Roles/Edit/{id}
    [HttpGet]
    public async Task<IActionResult> Edit(string id)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role is null) return NotFound();

        return View(new RoleVm { RoleId = role.Id, RoleName = role.Name! });
    }

    // POST: /Roles/Edit/{id}
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(RoleVm model)
    {
        //if (!ModelState.IsValid) return View(model);

        var role = await _roleManager.FindByIdAsync(model.RoleId!);
        if (role is null) return NotFound();

        role.Name = model.RoleName;
        var result = await _roleManager.UpdateAsync(role);
        if (!result.Succeeded)
        {
            foreach (var e in result.Errors) ModelState.AddModelError("", e.Description);
            return View(model);
        }

        TempData["Success"] = "Role updated.";
        return RedirectToAction(nameof(Index));
    }

    // POST: /Roles/Delete/{id}
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(string id)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role is null) return NotFound();

        // اختياري: منع حذف أدوار حرِجة
        if (string.Equals(role.Name, "SuperAdmin", StringComparison.OrdinalIgnoreCase))
        {
            TempData["Error"] = "Cannot delete SuperAdmin.";
            return RedirectToAction(nameof(Index));
        }

        var result = await _roleManager.DeleteAsync(role);
        TempData[result.Succeeded ? "Success" : "Error"] =
            result.Succeeded ? "Role deleted." : string.Join(", ", result.Errors.Select(e => e.Description));

        return RedirectToAction(nameof(Index));
    }

    // ====== إضافة/حذف دور لمستخدم ======

    // POST: /Roles/AddRoleToUser
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddRoleToUser(string userId, string roleName)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(roleName))
            return BadRequest();

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null) return NotFound("User not found.");

        if (!await _roleManager.RoleExistsAsync(roleName))
            return NotFound("Role not found.");

        var result = await _userManager.AddToRoleAsync(user, roleName);
        TempData[result.Succeeded ? "Success" : "Error"] =
            result.Succeeded ? $"Added '{roleName}' to {user.UserName}."
                             : string.Join(", ", result.Errors.Select(e => e.Description));

        return RedirectToAction(nameof(UsersWithRoles));
    }

    // POST: /Roles/RemoveRoleFromUser
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemoveRoleFromUser(string userId, string roleName)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null) return NotFound();

        var result = await _userManager.RemoveFromRoleAsync(user, roleName);
        TempData[result.Succeeded ? "Success" : "Error"] =
            result.Succeeded ? $"Removed '{roleName}' from {user.UserName}."
                             : string.Join(", ", result.Errors.Select(e => e.Description));

        return RedirectToAction(nameof(UsersWithRoles));
    }

    // GET: /Roles/UsersWithRoles
    [HttpGet]
    public async Task<IActionResult> UsersWithRoles()
    {
        var users = _userManager.Users.ToList();
        var model = new List<UserRolesVm>();
        foreach (var u in users)
        {
            var roles = await _userManager.GetRolesAsync(u); // IList<string>
            model.Add(new UserRolesVm
            {
                User = u,
                UserRoles =  roles.ToList() 

            });
        }

        ViewBag.RoleNames = _roleManager.Roles.Select(r => r.Name!).ToList();
        return View(model);
    }
}
