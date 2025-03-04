using Microsoft.AspNetCore.Identity;
using SafeVault.Controller;
using SafeVault.Models;
using SafeVault.Services;
using Moq;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace SafeVault.Test;

public class AuthControllerTests
{
    private readonly Mock<UserManager<ApplicationUser>> _mockUserManager;
    private readonly Mock<RoleManager<IdentityRole>> _mockRoleManager;
    private readonly Mock<JwtService> _mockJwtService;
    private readonly AuthController _authController;
    private readonly Mock<IPasswordHasher<ApplicationUser>> _mockPasswordHasher;

    public AuthControllerTests()
    {
        var userStoreMock = new Mock<IUserStore<ApplicationUser>>();
        _mockUserManager = new Mock<UserManager<ApplicationUser>>(
            userStoreMock.Object, null, null, null, null, null, null, null, null
        );

        var roleStoreMock = new Mock<IRoleStore<IdentityRole>>();
        _mockRoleManager = new Mock<RoleManager<IdentityRole>>(
            roleStoreMock.Object, null, null, null, null
        );

        _mockPasswordHasher = new Mock<IPasswordHasher<ApplicationUser>>();
        _mockUserManager.Object.PasswordHasher = _mockPasswordHasher.Object;

        var jwtSettings = new JwtSettings
        {
            SecretKey = "myverysecretkeythatnooneshouldknowaboutbutitishardcodedhere1",
            ValidIssuer = "TestIssuer",
            ValidAudience = "TestAudience",
            TokenLifetimeInMinutes = 60
        };

        var mockJwtSettings = new Mock<IOptions<JwtSettings>>();
        mockJwtSettings.Setup(s => s.Value).Returns(jwtSettings);

        var jwtService = new JwtService(mockJwtSettings.Object);

        _authController = new AuthController(_mockUserManager.Object, _mockRoleManager.Object, jwtService);
    }

    [Fact]
    public async Task Register_InvalidModelState_ReturnsBadRequest()
    {
        _authController.ModelState.AddModelError("error", "an error");
        var model = new User { Username = "testuser", Email = "testuser@example.com", Password = "password123" };

        var result = await _authController.Register(model);

        var assertResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("Register failed.", assertResult.Value);
    }

    [Fact]
    public async Task Register_ValidUser_ReturnsOk()
    {
        var model = new User { Username = "testuser", Email = "testuser@example.com", Password = "password123" };

        _mockUserManager.Setup(u => u.CreateAsync(It.IsAny<ApplicationUser>()));
        _mockUserManager.Setup(u => u.AddToRoleAsync(It.IsAny<ApplicationUser>(), "User"));

        var result = await _authController.Register(model);

        var assertResult = Assert.IsType<OkObjectResult>(result);
        Assert.Equal("User registered.", assertResult.Value);
    }

    [Fact]
    public async Task Register_UserCreationFail_ReturnBadRequest()
    {
        var model = new User { Username = "testuser", Email = "testuser@example.com", Password = "password123" };

        _mockUserManager.Setup(u => u.CreateAsync(It.IsAny<ApplicationUser>())).ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Error creating user." }));

        var result = await _authController.Register(model);

        var assertResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("Error creating user.", ((IEnumerable<IdentityError>)assertResult.Value).First().Description);
    }

    [Fact]
    public async Task Login_UserDontExist_ReturnsUnauthorized()
    {
        var model = new User { Username = "boogeyman", Password = "Password123" };

        _mockUserManager.Setup(u => u.FindByNameAsync(model.Username)).ReturnsAsync((ApplicationUser)null);

        var result = await _authController.Login(model);

        var assertResult = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal("Invalid username/password.", assertResult.Value);
    }

    [Fact]
    public async Task Login_InvalidPassword_ReturnsUnauthorized()
    {
        var user = new ApplicationUser { UserName = "testuser" };
        var loginUser = new User { Username = "testuser", Password = "notapassword" };

        var passwordHasher = new PasswordHasher<ApplicationUser>();
        user.PasswordHash = passwordHasher.HashPassword(user, "Password123");

        _mockUserManager.Setup(u => u.FindByNameAsync(loginUser.Username)).ReturnsAsync(user);
        _mockPasswordHasher.Setup(p => p.VerifyHashedPassword(user, user.PasswordHash, loginUser.Password)).Returns(PasswordVerificationResult.Failed);

        var result = await _authController.Login(loginUser);

        var assertResult = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal("Invalid username/password.", assertResult.Value);
    }

    [Fact]
    public async Task Login_ValidUser_ReturnsOkWithToken()
    {
        var user = new ApplicationUser {UserName = "testuser"};
        var loginUser = new User {Username = "testuser", Password = "Password123"};

        var passwordHasher = new PasswordHasher<ApplicationUser>();
        user.PasswordHash = passwordHasher.HashPassword(user, loginUser.Password);
        
        
        _mockUserManager.Setup(u => u.FindByNameAsync(loginUser.Username)).ReturnsAsync(user);
        _mockPasswordHasher.Setup(p => p.VerifyHashedPassword(user, user.PasswordHash, loginUser.Password)).Returns(PasswordVerificationResult.Success);

        var result = await _authController.Login(loginUser);

        var assertResult = Assert.IsType<OkObjectResult>(result);
        var token = ((dynamic)assertResult.Value).Token;
        Assert.NotNull(token);
    }

    [Fact]
    public async Task SeedRole_SeededRoles_ReturnOk()
    {
        _mockRoleManager.Setup(r=>r.RoleExistsAsync(It.IsAny<string>())).ReturnsAsync(false);
        _mockRoleManager.Setup(r=>r.CreateAsync(It.IsAny<IdentityRole>())).ReturnsAsync(IdentityResult.Success);

        var result = await _authController.SeedRoles();

        var assertResult = Assert.IsType<OkObjectResult>(result);
        Assert.Equal("Seeded roles", assertResult.Value);
    }
}