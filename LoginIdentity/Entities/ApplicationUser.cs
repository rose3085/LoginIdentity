using Microsoft.AspNetCore.Identity;

namespace LoginIdentity.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
