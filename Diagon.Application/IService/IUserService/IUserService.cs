using Diagon.Application.Service.Common;
using Diagon.Application.Service.UserService.Dto;

namespace Diagon.Application.IService.IUserService
{
    public interface IUserService
    {
      //  public UserDto CreateApplicationUserDto(User user);
        public Task<ApiResponse<UserDto>> UserLogin(LoginDto loginDto);
        public Task<ApiResponse<string>> RegisterUser(RegisterDto registerDto);
        public Task<ApiResponse<string>> EmailConfirmation(string token, string email);
    }
}
