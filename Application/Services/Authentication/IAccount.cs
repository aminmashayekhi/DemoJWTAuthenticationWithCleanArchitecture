using Application.DTOs;

namespace Application.Services.Authentication
{
    public interface IAccount
    {
        Task<RegisterationResponse> RegisterAccountAsync(RegisterUserDTO model);
        Task<LoginResponse> LoginAccountAsync(LoginDTO model);
    }
}
