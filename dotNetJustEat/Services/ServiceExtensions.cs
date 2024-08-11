using dotNetJustEat.Interfaces;

namespace dotNetJustEat.Services
{
    public static class ServiceExtensions
    {
        public static IServiceCollection RegisterAllServices(
            this IServiceCollection services,
            IConfiguration configuration
        )
        {
            services.AddScoped<IAuthService, AuthService>();

            return services;
        }
    }
}
