namespace dotNetJustEat.Services
{
    public static class ServiceExtensions
    {
        public static IServiceCollection RegisterAllServices(
            this IServiceCollection services,
            IConfiguration configuration
        )
        {
            return services;
        }
    }
}
