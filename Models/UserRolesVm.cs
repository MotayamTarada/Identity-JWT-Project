using Microsoft.AspNetCore.Identity;

namespace Identity_JWT_Project.Models
{
    public class UserRolesVm
    {
        
        public  UserRolesVm()
        {
            UserRoles = new List<string>();
        }

        public IdentityUser User { get; set; }

        public List<string> UserRoles { get; set; }
    }
}
