using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Helpers;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Controller
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JwtService _jwtService;

        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;

        public AuthController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, JwtService jwtService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwtService = jwtService;

            _passwordHasher = new PasswordHasher<ApplicationUser>();
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] User user)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (!ValidationHelper.IsValidXssInput(user.Username) || !ValidationHelper.IsValidXssInput(user.Email))
                return BadRequest("Potential danger content.");

            var u = new ApplicationUser
            {
                UserName = user.Username,
                Email = user.Email
            };

            u.PasswordHash = _passwordHasher.HashPassword(u, user.Password);
            var result = await _userManager.CreateAsync(u);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            await _userManager.AddToRoleAsync(u, "User");

            return Ok("User registered");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] User user)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (!ValidationHelper.IsValidInput(user.Username) || !ValidationHelper.IsValidXssInput(user.Username))
                return BadRequest("Invalid input");

            var u = await _userManager.FindByNameAsync(user.Username);

            if (u == null)
                return Unauthorized("Invalid username/password");

            var passwordVerification = _passwordHasher.VerifyHashedPassword(u, u.PasswordHash, user.Password);

            if (passwordVerification != PasswordVerificationResult.Success)
                return Unauthorized("Invalid username/password");

            var token = _jwtService.GenerateJwt(user.Username);

            return Ok(new { Token = token });
        }

        [Authorize]
        [HttpPost("logout")]
        public IActionResult Logout()
        {
            return Ok("Logged out");
        }

        [HttpPost("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var roles = new[] { "Admin", "User", "Guest" };

            foreach (var role in roles)
            {
                if (!await _roleManager.RoleExistsAsync(role))
                    await _roleManager.CreateAsync(new IdentityRole(role));
            };

            return Ok("Seeded roles");
        }
    }
}