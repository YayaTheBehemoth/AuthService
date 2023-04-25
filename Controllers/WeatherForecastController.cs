using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using UserDataService.UserService;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _config;

    private userService _service;

    public AuthController(ILogger<AuthController> logger, IConfiguration config, userService service)
    {
        _logger = logger;
        _config = config;
        _service = service;
    }
    private string GenerateJwtToken(string username)
{
var securityKey =
new
SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Secret"]));
var credentials =
new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
var claims = new[]
{
new Claim(ClaimTypes.NameIdentifier, username)
};
var token = new JwtSecurityToken(
_config["Issuer"],
"http://localhost",
claims,
expires: DateTime.Now.AddMinutes(15),
signingCredentials: credentials);
return new JwtSecurityTokenHandler().WriteToken(token);
}
    

    [HttpGet(Name = "GetForecast")]
    public IEnumerable<WeatherForecast> Get()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }
[AllowAnonymous]
[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginModel login)
{
if (_service.Login(login) == false)
{
 return Unauthorized();
}
var token = GenerateJwtToken(login.Username);
Console.WriteLine($"{token}");
return  Ok(new { token });
}
[AllowAnonymous]
[HttpPost("validate")]
public async Task<IActionResult> ValidateJwtToken([FromBody] string? token)
{
    Console.WriteLine($"{token}");
if (token.IsNullOrEmpty())

return BadRequest("Invalid token submited.");
var tokenHandler = new JwtSecurityTokenHandler();
var key = Encoding.ASCII.GetBytes(_config["Secret"]!);
try
{
tokenHandler.ValidateToken(token, new TokenValidationParameters
{
ValidateIssuerSigningKey = true,
IssuerSigningKey = new SymmetricSecurityKey(key),
ValidateIssuer = false,
ValidateAudience = false,
ClockSkew = TimeSpan.Zero
}, out SecurityToken validatedToken);
var jwtToken = (JwtSecurityToken)validatedToken;
var accountId = jwtToken.Claims.First(
x => x.Type == ClaimTypes.NameIdentifier).Value;
return Ok(accountId);
}
catch (Exception ex)
{

_logger.LogError(ex, ex.Message);
return StatusCode(404);
}
}
}
