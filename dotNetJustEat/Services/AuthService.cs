using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using dotNetJustEat.Context;
using dotNetJustEat.DTOs;
using dotNetJustEat.Entities;
using dotNetJustEat.Interfaces;
using dotNetJustEat.Util;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace dotNetJustEat.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<UserCredentials> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<UserCredentials> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _db;

        private const int TokenExpirationTime = 1; // 1 hour

        public AuthService(
            UserManager<UserCredentials> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<UserCredentials> signInManager,
            IConfiguration configuration,
            ApplicationDbContext db
        )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _db = db;
        }

        public async Task<LoginResponse> Login(LoginRequest login)
        {
            try
            {
                var result = await _signInManager.PasswordSignInAsync(
                    login.Email,
                    login.Password,
                    true,
                    lockoutOnFailure: false
                );

                if (!result.Succeeded)
                    throw new Exception("Invalid credentials");
                if (result.IsLockedOut)
                    throw new Exception("User is locked out");

                var user = await _userManager.FindByEmailAsync(login.Email);

                if (user == null)
                    throw new Exception("User not found");

                var accessToken = GenerateToken(user);
                var refreshToken = GenerateToken(user);

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
                return new LoginResponse
                {
                    AccessToken = accessToken,
                    Duration = TokenExpirationTime * 60 * 60, // converto in secondi
                    RefreshToken = refreshToken
                };
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public async Task<RefreshTokenResponse> RefreshToken(
            RefreshTokenRequest refreshTokenRequest
        )
        {
            try
            {
                var accessTokenUserId = GetIdFromToken(refreshTokenRequest.AccessToken);
                var refreshTokenUserId = GetIdFromToken(refreshTokenRequest.RefreshToken);

                if (refreshTokenUserId == null)
                    throw new Exception("The refresh token has expired or is invalid.");
                if (accessTokenUserId != refreshTokenUserId)
                    throw new Exception(
                        "The user ID in the access token does not match the user ID in the refresh token."
                    );

                var user = _userManager.FindByIdAsync(accessTokenUserId).Result;

                if (user == null)
                    throw new Exception("Invalid client request");

                var storedRefreshToken = _userManager
                    .GetAuthenticationTokenAsync(user, "MyApp", "RefreshToken")
                    .Result;

                if (storedRefreshToken != refreshTokenRequest.RefreshToken)
                    throw new Exception("Invalid refresh token");

                var newAccessToken = GenerateToken(user);
                var newRefreshToken = GenerateToken(user);

                if (newAccessToken == null || newRefreshToken == null)
                    throw new Exception("Error generating tokens");

                var token = new IdentityUserToken<string>
                {
                    UserId = user.Id,
                    LoginProvider = "MyApp",
                    Name = "RefreshToken",
                    Value = newRefreshToken
                };

                var setRefreshTokenResponse = _userManager.SetAuthenticationTokenAsync(
                    user,
                    token.LoginProvider,
                    token.Name,
                    token.Value
                );

                if (!setRefreshTokenResponse.Result.Succeeded)
                    throw new Exception("Error updating refresh token");

                return new RefreshTokenResponse
                {
                    AccessToken = newAccessToken,
                    Duration = TokenExpirationTime * 60 * 60, // converto in secondi
                    RefreshToken = newRefreshToken
                };
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public async Task<UserRegisterResponse> Register(UserRegisterRequest registerRequest)
        {
            using (var transaction = await _db.Database.BeginTransactionAsync())
            {
                try
                {
                    var user = new UserCredentials
                    {
                        UserName = registerRequest.Email,
                        Email = registerRequest.Email
                    };
                    var result = await _userManager.CreateAsync(user, registerRequest.Password);

                    if (!result.Succeeded)
                        throw new Exception("Error creating user");

                    UserRegistry userRegistry = new UserRegistry
                    {
                        UserCredentialsId = user.Id,
                        Name = registerRequest.Name,
                        Surname = registerRequest.Surname,
                        Address = registerRequest.Address,
                        City = registerRequest.City,
                        CAP = registerRequest.CAP,
                        MobileNumber = registerRequest.MobileNumber
                    };

                    var addRoleResult = await _userManager.AddToRoleAsync(user, Roles.ADMIN);

                    if (!addRoleResult.Succeeded)
                        throw new Exception("Error adding role to user");

                    _db.UserRegistries.Add(userRegistry);
                    _db.SaveChanges();
                    await transaction.CommitAsync();

                    return new UserRegisterResponse { Success = true, NewUserId = user.Id };
                }
                catch (Exception ex)
                {
                    await transaction.RollbackAsync();
                    throw new Exception(ex.Message);
                }
            }
        }

        public IdentityResult AddUserRole(string userId, string role)
        {
            throw new NotImplementedException();
        }

        public IdentityResult CreateRole(string roleName)
        {
            throw new NotImplementedException();
        }

        private string GenerateToken(UserCredentials user)
        {
            try
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
                    Expires = DateTime.UtcNow.AddHours(TokenExpirationTime),
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
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        private string GetIdFromToken(string token)
        {
            try
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
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }
    }
}
