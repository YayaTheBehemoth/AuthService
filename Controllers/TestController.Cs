using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Controllers;
[ApiController]
[Route("[controller]")]
public class testController : ControllerBase
{

[Authorize]
[HttpGet]
public async Task<IActionResult> Get()
{
return Ok("You're authorized");
}
}