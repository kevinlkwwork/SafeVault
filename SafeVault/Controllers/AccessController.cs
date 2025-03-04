using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SafeVault.Controller
{
    [ApiController]
    [Route("api/Data")]
    public class AccessController : ControllerBase
    {
        [HttpGet("admin")]
        [Authorize(Policy = "AdminPolicy")]
        public IActionResult GetAdminData()
        {
            return Ok("Admin only access");
        }

        [HttpGet("user")]
        [Authorize(Policy = "UserPolicy")]
        public IActionResult GetUserData()
        {
            return Ok("User only access");
        }

        [HttpGet("guest")]
        [Authorize(Policy = "GuestPolicy")]
        public IActionResult GetGuestData()
        {
            return Ok("Guest only access");
        }
    }
}