using Azure;
using Diagon.Application.IService.IUserService;
using Diagon.Application.Service.Common;
using Diagon.Application.Service.UserService.Dto;
using Diagon.Domain.Users;
using Microsoft.AspNet.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Data;

namespace Diagon.Web.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;

        public AuthController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("login")]
        public async Task<ActionResult<ApiResponse<UserDto>>> Login(LoginDto loginDto)
        {
            var response = await _userService.UserLogin(loginDto);

            if (response.Success)
            {
                return Ok(response); // 200 OK with the ApiResponse<UserDto>
            }
            else
            {
                return BadRequest(response); // 400 Bad Request with the ApiResponse<UserDto>
            }

        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto registerDto)
        {
            var responseResult = await _userService.RegisterUser(registerDto);

            // Check user exist or not
            if (responseResult.Success)
            {
                return Ok(responseResult); // 200 OK with the ApiResponse<UserDto>
            }
            else
            {
                return BadRequest(responseResult); // 400 Bad Request with the ApiResponse<UserDto>
            }

        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var responseResult = await _userService.EmailConfirmation(token, email);

            // Check user exist or not
            if (responseResult.Success)
            {
                return Ok(responseResult); // 200 OK with the ApiResponse<UserDto>
            }
            else
            {
                return BadRequest(responseResult); // 400 Bad Request with the ApiResponse<UserDto>
            }

        }

        [HttpPost]
        [AllowAnonymous]
        [Route("forgotpassword")]
        public async Task<IActionResult> ForgorPassword([Required] string email)
        {
            var responseResult = await _userService.ForgetPassword(email);

            // Check user exist or not
            if (responseResult.Success)
            {
                return Ok(responseResult); // 200 OK with the ApiResponse<UserDto>
            }
            else
            {
                return BadRequest(responseResult); // 400 Bad Request with the ApiResponse<UserDto>
            }
        }

        [HttpGet("resetpassword")]
        public async Task<IActionResult> Resetpassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new
            {
                model
            });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("updatepassword")]
        public async Task<IActionResult> UpdatePassword(ResetPassword resetPassword)
        {
            var responseResult = await _userService.UpdatePassword(resetPassword);

            // Check user exist or not
            if (responseResult.Success)
            {
                return Ok(responseResult); // 200 OK with the ApiResponse<UserDto>
            }
            else
            {
                return BadRequest(responseResult); // 400 Bad Request with the ApiResponse<UserDto>
            }
        }
    }
}
