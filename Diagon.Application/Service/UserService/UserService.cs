using Diagon.Application.IService;
using Diagon.Application.IService.IUserService;
using Diagon.Application.Service.Common;
using Diagon.Application.Service.UserService.Dto;
using Diagon.Domain.Users;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Org.BouncyCastle.Asn1.Ocsp;

namespace Diagon.Application.Service.UserService
{
    public class UserService : IUserService
    {
        private readonly JWTService _jWTService;
        private readonly SignInManager<User> _signInManager;
        private readonly IMailService _mailService;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<User> _userManager;
        private readonly IHttpContextAccessor _httpContextAccessor;


        public UserService(JWTService jWTService , SignInManager<User> signInManager,IMailService mailService,
           RoleManager<IdentityRole> roleManager, UserManager<User> userManager, IHttpContextAccessor httpContextAccessor) 
        {
            _jWTService = jWTService;
            _signInManager = signInManager;
            _mailService = mailService;
            _roleManager = roleManager;
            _userManager = userManager;
            _httpContextAccessor = httpContextAccessor; 
        }
      
        private ApiResponse<T> CreateResponse<T>(bool status, T data, string message, List<string>? erros)
        {
            return new ApiResponse<T>
            {
                Success = status,
                Data = data,
                Message = message,
                Errors = erros
            };
        }

        private string GetBaseUrl()
        {
            var request = _httpContextAccessor.HttpContext.Request;
            return $"{request.Scheme}://{request.Host.ToUriComponent()}{request.PathBase}";
        }
        private UserDto CreateApplicationUserDto(User user)
        {
            return new UserDto
            {
                UserName = user.UserName,
                JWT = _jWTService.CreateJWT(user)
            };
        }

        public async Task<ApiResponse<UserDto>> UserLogin(LoginDto loginDto)
        {
            try
            {
                if (loginDto == null)
                {
                    return CreateResponse<UserDto>(false, null, "User name or password cannot be null", null);                   
                }

                var user = await _userManager.FindByNameAsync(loginDto.UserName);

                if (user != null && await _userManager.CheckPasswordAsync(user, loginDto.Password))
                {
                    var userDto = CreateApplicationUserDto(user);
                    return CreateResponse<UserDto>(true, userDto, "Login Successfully", null);
                   
                }

                return CreateResponse<UserDto>(false, null, "Invalid User name or Password", null);
               
            }
            catch (Exception ex)
            {
                return CreateResponse<UserDto>(false, null, ex.Message, null);
               
            }
        }

        public async Task<ApiResponse<string>> RegisterUser(RegisterDto registerDto)
        {
            try
            {
                if (registerDto == null)
                {
                    return CreateResponse<string>(false,null,"UserName, Email and Password not be Empty", null);                  
                }

                var isExist = await _userManager.FindByEmailAsync(registerDto.Email);
                if (isExist != null)
                {
                    return CreateResponse<string>(false,null,"This email is already exist", null);                  
                   
                }

                var user = new User
                {
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = registerDto.UserName.ToLower(),
                    Email = registerDto.Email,
                    TwoFactorEnabled = false
                };

                var result = await _userManager.CreateAsync(user, registerDto.Password);
                if (!result.Succeeded)
                {
                    List<string> errorMessages = result.Errors.Select(error => error.Description).ToList();
                    return CreateResponse<string>( false, null, "User has failed to create", errorMessages);                  

                }
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                string baseUrl = GetBaseUrl();
                string confirmationLink = $"{baseUrl}/api/Auth/ConfirmEmail?token={Uri.EscapeDataString(token)}&email={Uri.EscapeDataString(user.Email)}";

                var message = new Message(new string[] { user.Email }, "Confirmation Email Link", confirmationLink);

                _mailService.SendEmail(message);
                return CreateResponse<string>(true, null, $"User Created and mail sent o {user.Email} successfully!", null);
               
               
            }
            catch (Exception ex)
            {
                return CreateResponse<string>(false, null, ex.Message, null);
            }
        }

        public async Task<ApiResponse<string>> EmailConfirmation(string token, string email)
        {
            try
            {
                if(string.IsNullOrEmpty(token) && string.IsNullOrEmpty(email))
                {
                    return CreateResponse<string>(false, null, "email and token is mendatory for verify", null);
                      
                }
                else
                {
                    var user = await _userManager.FindByEmailAsync(email);
                    if (user != null)
                    {
                        var result = await _userManager.ConfirmEmailAsync(user, token);
                        if (result.Succeeded)
                        {
                            return CreateResponse<string>(true, null, "Email Verified Successfully", null);                                                     
                        }

                    }
                    return CreateResponse<string>(false, null, "This user is not exist !", null);                                  
                }
              
            }
            catch (Exception ex)
            {
                return CreateResponse<string>(false, null,ex.Message, null);
            }
        }

        public async Task<ApiResponse<string>> ForgetPassword(string email)
        {
            try
            {
                if (email == null)
                {
                    return CreateResponse<string>(false, null, "Email should not be Null", null);                 
                }
                var user = await _userManager.FindByEmailAsync(email);
                if (user != null)
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    string baseUrl = GetBaseUrl();
                    var forgotpasswordLink = $"{baseUrl}/api/Auth/resetpassword?token={Uri.EscapeDataString(token)}&email={Uri.EscapeDataString(user.Email)}";
                
                    var message = new Message(new string[] { user.Email }, "Forgot Password Link", forgotpasswordLink);
                    _mailService.SendEmail(message);
                    return CreateResponse<string>(true, null, $"Password Change Request sent this mail { user.Email} successfully!", null);                 
                    
                }
                else
                {
                    return CreateResponse<string>(false, null, "This Email is not exist", null);

                }
            }
            catch (Exception ex)
            {
                return CreateResponse<string>(false, null,ex.Message, null);
            }
        }
    }
}
