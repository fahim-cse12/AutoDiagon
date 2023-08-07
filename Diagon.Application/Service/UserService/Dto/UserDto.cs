using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Diagon.Application.Service.UserService.Dto
{
    public class UserDto
    {
        public string UserName { get; set; }
        public string JWT { get; set; }
    }
}
