using dotNetJustEat.DTOs;
using Microsoft.AspNetCore.Identity;

namespace dotNetJustEat.Interfaces
{
    public interface IAuthService
    {
        public Task<LoginResponse> Login(LoginRequest loginRequest);
        public Task<UserRegisterResponse> Register(UserRegisterRequest registerRequest);
        public Task<RefreshTokenResponse> RefreshToken(RefreshTokenRequest refreshTokenRequest);
        public IdentityResult AddUserRole(string userId, string role);
        public IdentityResult CreateRole(string roleName);
    }
}
