using LoginIdentity.DTO;
using LoginIdentity.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LoginIdentity.Services
{
    public class AuthServices : IAuthServices
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthServices(UserManager<ApplicationUser> userManager, IConfiguration configuration, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }
        public async Task<ResponseMessage> Login(LoginDto model)
        {
            var userLogin = await _userManager.FindByNameAsync(model.UserName);
            if (userLogin is null)
            {
                return new ResponseMessage()
                {
                    IsSuccess = false,
                    Message = "Invalid Credentials, UserName already exist",
                };
            }
            var isPasswordCorrect = await _userManager.CheckPasswordAsync(userLogin, model.Password);
            if (!isPasswordCorrect)
            {
                return new ResponseMessage()
                {
                    IsSuccess = false,
                    Message = "Invalid Credentials, invalid password",
                };
            }
            // to clain user role
            var userRoles = await _userManager.GetRolesAsync(userLogin);

            var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, userLogin.UserName),
             new Claim(ClaimTypes.NameIdentifier, userLogin.Id),
              new Claim("JWTID", Guid.NewGuid().ToString()),
              new Claim("FirstName",userLogin.FirstName),
              new Claim("LastName", userLogin.LastName),
        };
            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            // to convert claims to token
            var token = GenerateNewJsonWebToken(authClaims);
            return new ResponseMessage()
            {
                IsSuccess = true,
                Message = "",
            };
        }

        public async Task<ResponseMessage> MakeAdmin(UpdatePermissionDto model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user is null)
            {
                return new ResponseMessage()
                {
                    IsSuccess = false,
                    Message = "Couldn't make user admin"
                };
            }
            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);
            return new ResponseMessage()
            {
                IsSuccess = true,
                Message = "User is sucessfully made admin"
            };
        }

        public async Task<ResponseMessage> MakeOwner(UpdatePermissionDto model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user is null)
            {
                return new ResponseMessage()
                {
                    IsSuccess = false,
                    Message = "Couldn't make user owner"
                };
            }
            await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);
            return new ResponseMessage()
            {
                IsSuccess = true,
                Message = "User is sucessfully made owner"
            };
        }

        public async Task<ResponseMessage> Register(RegisterDto model)
        {
            var userExists = await _userManager.FindByNameAsync(model.UserName);
            if (userExists != null)
            {
                return new ResponseMessage()
                {
                    IsSuccess = false,
                    Message = "Username already taken."
                };
            }
            ApplicationUser newUser = new ApplicationUser()
            {
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
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
                return new ResponseMessage()
                {
                    IsSuccess = false,
                    Message = error
                };
            }

            // add default role as user to all
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return new ResponseMessage()
            {
                IsSuccess = true,
                Message = " New user created sucessfully"
            };
        }

        public async Task<ResponseMessage> SeedRolesAsync()
        {
            // receives a string of roles
            bool isOwnerRolesExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isUserRolesExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);
            bool isAdminRolesExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            if (isUserRolesExists && isAdminRolesExists && isOwnerRolesExists)
            {
                return new ResponseMessage()
                {
                    IsSuccess = true,
                    Message = "Role Seeding already done"
                };
            }

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));

            return new ResponseMessage()
            {
                IsSuccess = true,
                Message = "Role Seedingdone successfully"
            };
        }
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
