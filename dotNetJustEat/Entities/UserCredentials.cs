using Microsoft.AspNetCore.Identity;

namespace dotNetJustEat.Entities
{
    public class UserCredentials : IdentityUser
    {
        public virtual UserRegistry UserRegistry { get; set; }
        public virtual CompanyRegistry CompanyRegistry { get; set; }
    }
}
