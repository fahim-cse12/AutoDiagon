using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Diagon.Application.Service.UserService.Dto
{
    public class RegisterDto
    {

        [Required(ErrorMessage = "User Name is required")]
        public string UserName { get; set; }
        [Required]
      //  [RegularExpression("^\\w+@[a-zA-Z_]+?\\.[a-zA-Z]{2,3}$", ErrorMessage = "Invalid Email address")]
        public string Email { get; set; }
        [Required]
        [StringLength(15, MinimumLength = 6, ErrorMessage = "Password should be 6 digit")]
        public string Password { get; set; }
    }
}
