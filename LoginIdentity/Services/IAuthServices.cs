using LoginIdentity.DTO;
using Microsoft.AspNetCore.Mvc;

namespace LoginIdentity.Services
{
    public interface IAuthServices
    {
        Task<ResponseMessage> SeedRolesAsync();
        Task<ResponseMessage> Register(RegisterDto model);
        Task<ResponseMessage> Login(LoginDto model);
        Task<ResponseMessage> MakeAdmin(UpdatePermissionDto model);
        Task<ResponseMessage> MakeOwner(UpdatePermissionDto model);
    }
}
