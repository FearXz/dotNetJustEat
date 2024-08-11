using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using dotNetJustEat.DTOs;
using dotNetJustEat.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace dotNetJustEat.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<UserCredentials> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<UserCredentials> _signInManager;
        private readonly IConfiguration _configuration;

        public AuthController(
            UserManager<UserCredentials> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<UserCredentials> signInManager,
            IConfiguration configuration
        )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpPost("AddUserRole")]
        public async Task<IActionResult> AddUserRole(string userId, string role)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound("User not found");
            }

            var result = await _userManager.AddToRoleAsync(user, role);
            if (result.Succeeded)
            {
                return Ok("Role added to user");
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("CreateRole")]
        public async Task<IActionResult> CreateRole(string roleName)
        {
            if (string.IsNullOrEmpty(roleName))
            {
                return BadRequest("Role name cannot be empty");
            }

            var roleExists = await _roleManager.RoleExistsAsync(roleName);
            if (roleExists)
            {
                return BadRequest("Role already exists");
            }

            var result = await _roleManager.CreateAsync(new IdentityRole(roleName));
            if (result.Succeeded)
            {
                return Ok("Role created successfully");
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _signInManager.PasswordSignInAsync(
                model.Email,
                model.Password,
                true,
                lockoutOnFailure: false
            );

            if (result.Succeeded)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                var accessToken = GenerateJwtToken(user);
                var refreshToken = GenerateRefreshToken();

                var token = new IdentityUserToken<string>
                {
                    UserId = user.Id,
                    LoginProvider = "MyApp",
                    Name = "RefreshToken",
                    Value = refreshToken
                };

                await _userManager.SetAuthenticationTokenAsync(
                    user,
                    token.LoginProvider,
                    token.Name,
                    token.Value
                );

                return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
            }

            if (result.IsLockedOut)
            {
                return BadRequest(new { Message = "User account locked out." });
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return BadRequest(ModelState);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = new UserCredentials { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return Ok(new { Message = "User registered successfully" });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return BadRequest(ModelState);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var principal = GetPrincipalFromExpiredToken(model.AccessToken);
            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return BadRequest("Invalid client request");
            }

            var storedRefreshToken = await _userManager.GetAuthenticationTokenAsync(
                user,
                "MyApp",
                "RefreshToken"
            );

            if (storedRefreshToken != model.RefreshToken || storedRefreshToken == null)
            {
                return BadRequest("Invalid refresh token");
            }

            var newAccessToken = GenerateJwtToken(user);
            var newRefreshToken = GenerateRefreshToken();

            await _userManager.SetAuthenticationTokenAsync(
                user,
                "MyApp",
                "RefreshToken",
                newRefreshToken
            );

            return Ok(
                new
                {
                    AccessToken = newAccessToken,
                    Duration = 3600,
                    RefreshToken = newRefreshToken
                }
            );
        }

        private string GenerateJwtToken(UserCredentials user)
        {
            var jwt = _configuration.GetSection("Jwt");
            var key = Encoding.ASCII.GetBytes(jwt["Key"]);

            var claims = new[]
            {
                new Claim("email", user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Genera un jti unico
                new Claim(ClaimTypes.NameIdentifier, user.Id), // Memorizza l'ID utente qui
                new Claim(ClaimTypes.Name, user.UserName) // Memorizza il nome utente qui
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature
                ),
                Issuer = jwt["Issuer"],
                Audience = jwt["Audience"]
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])
                ),
                ValidateLifetime = false // here we are saying that we don't care about the token's expiration date
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(
                token,
                tokenValidationParameters,
                out SecurityToken securityToken
            );
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (
                jwtSecurityToken == null
                || !jwtSecurityToken.Header.Alg.Equals(
                    SecurityAlgorithms.HmacSha256,
                    StringComparison.InvariantCultureIgnoreCase
                )
            )
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }
    }
}
