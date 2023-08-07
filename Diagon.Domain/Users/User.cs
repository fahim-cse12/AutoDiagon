using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Diagon.Domain.Users
{
    public class User : IdentityUser
    {
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow; 
    }
}
