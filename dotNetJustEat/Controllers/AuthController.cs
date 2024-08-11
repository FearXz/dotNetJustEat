using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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
                var accessToken = GenerateToken(user); // 1 ora per l'access token
                var refreshToken = GenerateToken(user); // 90 giorni per il refresh token (90 * 24 ore)

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

                return Ok(
                    new
                    {
                        AccessToken = accessToken,
                        Duration = 3600,
                        RefreshToken = refreshToken
                    }
                );
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

            try
            {
                var accessTokenUserId = GetIdFromToken(model.AccessToken);
                var refreshTokenUserId = GetIdFromToken(model.RefreshToken);

                if (refreshTokenUserId == null)
                {
                    return BadRequest("The refresh token has expired or is invalid.");
                }
                if (accessTokenUserId != refreshTokenUserId)
                {
                    return BadRequest(
                        "The user ID in the access token does not match the user ID in the refresh token."
                    );
                }

                var user = await _userManager.FindByIdAsync(accessTokenUserId);

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

                var newAccessToken = GenerateToken(user); // 1 ora per l'access token
                var newRefreshToken = GenerateToken(user); // 90 giorni per il refresh token (90 * 24 ore)

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
            catch (SecurityTokenExpiredException)
            {
                return BadRequest("The access token has expired.");
            }
            catch (SecurityTokenException)
            {
                return BadRequest("Invalid access token.");
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }

        private string GenerateToken(UserCredentials user)
        {
            var jwt = _configuration.GetSection("Jwt");
            var key = Encoding.ASCII.GetBytes(jwt["Key"]);

            var claims = new[]
            {
                new Claim("Email", user.Email),
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

        private string GetIdFromToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])
                ),
                ValidateLifetime = false // Non validare la scadenza del token
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

            return principal.FindFirstValue(ClaimTypes.NameIdentifier);
        }
    }
}
