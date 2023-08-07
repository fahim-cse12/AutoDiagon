using Diagon.Application.IService;
using Diagon.Application.IService.IUserService;
using Diagon.Application.Service.Common;
using Diagon.Application.Service.UserService.Dto;
using Diagon.Domain.Users;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Diagnostics;
using System.Security.Policy;
using System.Text;

namespace Diagon.Application.Service.UserService
{
    public class UserService : IUserService
    {
        private readonly JWTService _jWTService;
        private readonly SignInManager<User> _signInManager;
        private readonly IMailService _mailService;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<User> _userManager;
       

        public UserService(JWTService jWTService , SignInManager<User> signInManager,IMailService mailService,
           RoleManager<IdentityRole> roleManager, UserManager<User> userManager) 
        {
            _jWTService = jWTService;
            _signInManager = signInManager;
            _mailService = mailService;
            _roleManager = roleManager;
            _userManager = userManager;
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
                    ApiResponse<UserDto> nullResponse = new ApiResponse<UserDto>
                    {
                        Success = false,
                        Data = null,
                        Message = "User name or password cannot be null",
                        Errors = null
                    };
                    return nullResponse;
                }

                var user = await _userManager.FindByNameAsync(loginDto.UserName);

                if (user != null && await _userManager.CheckPasswordAsync(user, loginDto.Password))
                {
                    var userDto = CreateApplicationUserDto(user);
                    ApiResponse<UserDto> successResponse = new ApiResponse<UserDto>
                    {
                        Success = true,
                        Data = userDto,
                        Message = "Login Successfully",
                        Errors = null
                    };
                    return successResponse;
                }

                ApiResponse<UserDto> invalidResponse = new ApiResponse<UserDto>
                {
                    Success = false,
                    Data = null,
                    Message = "Invalid User name or Password",
                    Errors = null
                };
                return invalidResponse;
            }
            catch (Exception ex)
            {
                ApiResponse<UserDto> errorResponse = new ApiResponse<UserDto>
                {
                    Success = false,
                    Data = null,
                    Message = ex.Message,
                    Errors = null
                };
                return errorResponse;
            }
        }

        public async Task<ApiResponse<string>> RegisterUser(RegisterDto registerDto)
        {
            try
            {
                if (registerDto == null)
                {
                    ApiResponse<string> nullResponse = new ApiResponse<string>
                    {
                        Success = false,
                        Data = null,
                        Message = "UserName, Email and Password not be Empty",
                        Errors = null
                    };
                    return nullResponse;
                }

                var isExist = await _userManager.FindByEmailAsync(registerDto.Email);
                if (isExist != null)
                {
                    ApiResponse<string> existResponse = new ApiResponse<string>
                    {
                        Success = false,
                        Data = null,
                        Message = "This email is already exist",
                        Errors = null
                    };
                    return existResponse;
                   
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
                    ApiResponse<string> errorCreateResponse = new ApiResponse<string>
                    {
                        Success = false,
                        Data = null,
                        Message = "User has failed to create",
                        Errors = errorMessages
                    };
                    return errorCreateResponse;
                    //  return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Failed to Create" });

                }
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            //var confirmationLink = _urlHelper.Action("ConfirmEmail", "Auth", new { token, user.Email });

                var confirmationLink = "http://localhost:5115/api/Auth/ConfirmEmail?token=" + token + "&email=" + user.Email;
                var message = new Message(new string[] { user.Email }, "Confirmation Email Link", confirmationLink);

                _mailService.SendEmail(message);

                ApiResponse<string> roleResponse = new ApiResponse<string>
                {
                    Success = true,
                    Data = null,
                    Message = $"User Created and mail sent o {user.Email} successfully!",
                    Errors = null
                };
                return roleResponse;
               
            }
            catch (Exception ex)
            {
                ApiResponse<string> errorResponse = new ApiResponse<string>
                {
                    Success = false,
                    Data = null,
                    Message = ex.Message,
                    Errors = null
                };
                return errorResponse;
            }
        }

        public async Task<ApiResponse<string>> EmailConfirmation(string token, string email)
        {
            try
            {
                if(string.IsNullOrEmpty(token) && string.IsNullOrEmpty(email))
                {
                    ApiResponse<string> nullResponse = new ApiResponse<string>
                    {
                        Success = false,
                        Data = null,
                        Message = "email and token is mendatory for verify",
                        Errors = null
                    };
                    return nullResponse;
                }
                else
                {
                    var user = await _userManager.FindByEmailAsync(email);
                    if (user != null)
                    {
                        var result = await _userManager.ConfirmEmailAsync(user, token);
                        if (result.Succeeded)
                        {
                            ApiResponse<string> successResponse = new ApiResponse<string>
                            {
                                Success = true,
                                Data = null,
                                Message = "Email Verified Successfully",
                                Errors = null
                            };
                            return successResponse;
                           
                        }

                    }
                    ApiResponse<string> failsResponse = new ApiResponse<string>
                    {
                        Success = true,
                        Data = null,
                        Message = "This user is not exist !",
                        Errors = null
                    };
                    return failsResponse;                   

                }
              
            }
            catch (Exception ex)
            {
                ApiResponse<string> exceptionResponse = new ApiResponse<string>
                {
                    Success = false,
                    Data = null,
                    Message = ex.Message,
                    Errors = null
                };
                return exceptionResponse;
            }
        }
    }
}
