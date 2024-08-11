using dotNetJustEat.Context;
using dotNetJustEat.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace dotNetJustEat.Services
{
    public class EUserManager : UserManager<UserCredentials>
    {
        private readonly ApplicationDbContext _db;

        public EUserManager(
            IUserStore<UserCredentials> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<UserCredentials> passwordHasher,
            IEnumerable<IUserValidator<UserCredentials>> userValidators,
            IEnumerable<IPasswordValidator<UserCredentials>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<UserCredentials>> logger,
            ApplicationDbContext db
        )
            : base(
                store,
                optionsAccessor,
                passwordHasher,
                userValidators,
                passwordValidators,
                keyNormalizer,
                errors,
                services,
                logger
            )
        {
            _db = db;
        }

        public async Task<UserRegistry> AddUserRegistriesAsync(UserRegistry userRegistry)
        {
            try
            {
                await _db.UserRegistries.AddAsync(userRegistry);
                await _db.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }

            return userRegistry;
        }
    }
}
