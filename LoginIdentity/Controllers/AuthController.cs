using LoginIdentity.DTO;
using Microsoft.AspNetCore.Http;
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
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthController(UserManager<IdentityUser> userManager,IConfiguration configuration, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        // route for seeding roles to DB
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            // receives a string of roles
            bool isOwnerRolesExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isUserRolesExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);
            bool isAdminRolesExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            if (isUserRolesExists && isAdminRolesExists && isOwnerRolesExists)
            {
                return Ok("Roles seeding is already done");
            }

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));

            return Ok("Role Seeding Done Successfully");
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            var userExists = await _userManager.FindByNameAsync(model.UserName);
            if (userExists != null)
            {
                return BadRequest("User already exists");
            }
            IdentityUser newUser = new IdentityUser()
            {
                Email = model.Email,
                UserName = model.UserName,
                SecurityStamp = Guid.NewGuid().ToString()
            };
            var createUser = await _userManager.CreateAsync(newUser, model.Password);
            if (!createUser.Succeeded)
            {
                var error = "User creation failed :";
                foreach (var errors in createUser.Errors)
                {
                    error += " # " + errors.Description;
                }
                return BadRequest(error);
            }

            // add default role as user to all
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return Ok("User created successfully");
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            var userLogin = await _userManager.FindByNameAsync(model.UserName);
            if (userLogin is null)
            {
                return Unauthorized("Invalid Credentials");
            }
            var isPasswordCorrect = await _userManager.CheckPasswordAsync(userLogin, model.Password);
            if (!isPasswordCorrect) 
            {
                return Unauthorized("Invalid Credentials");
            }
            // to clain user role
            var userRoles = await _userManager.GetRolesAsync(userLogin);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, userLogin.UserName),
                 new Claim(ClaimTypes.NameIdentifier, userLogin.Id),
                  new Claim("JWTID", Guid.NewGuid().ToString()),
            };
            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            // to convert claims to token
            var token = GenerateNewJsonWebToken(authClaims);
            return Ok(token);
        }


        // to create new token
        private string GenerateNewJsonWebToken(List<Claim> claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var tokenObject = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: claims,
                signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );
            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);
            return token;
        }

    }
}