using LoginIdentity.DTO;
using LoginIdentity.Entities;
using LoginIdentity.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LoginIdentity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthServices _authServices;
        public AuthController(AuthServices authServices)
        {
            _authServices = authServices;
        }

        // route for seeding roles to DB
        [HttpPost]
        [Route("seed-roles")]
        public async Task<ActionResult<ResponseMessage>> SeedRoles()
        {
            
            var seedRoles = await _authServices.SeedRolesAsync();
            return Ok(seedRoles);
        }

        [HttpPost]
        [Route("Register")]
        public async Task<ActionResult<ResponseMessage>> Register([FromBody] RegisterDto model)
        {
            var registerResult = await _authServices.Register(model);

            if ((bool)registerResult.IsSuccess)
                return Ok(registerResult);

            return BadRequest(registerResult);
        }

        [HttpPost]
        [Route("Login")]
        public async Task<ActionResult<ResponseMessage>> Login([FromBody] LoginDto model)
        {

            var result = await _authServices.Login(model);

            if ((bool)result.IsSuccess)
            {
                return Ok(result);
            }

            return BadRequest(result);
        }



        //route to make user a admin
        [HttpPost]
        [Route("make-admin")]
        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDto model)
        {
            var result = await _authServices.MakeAdmin(model);

            if ((bool) result.IsSuccess)
                return Ok(result);

            return BadRequest(result);
        }

        // route to make a user owner

        [HttpPost]
        [Route("make-owner")]
        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDto model)
        {
            var result = await _authServices.MakeOwner(model);

            if ((bool)result.IsSucceedded)
                return Ok(result);

            return BadRequest(result);
        }

    }
}