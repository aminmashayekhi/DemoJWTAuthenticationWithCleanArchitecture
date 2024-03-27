using Application.Contracts;
using Application.DTOs;
using Domain.Entities;
using Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Repo
{
    internal class UserRepo : IUser
    {
        private readonly AppDbContext appDbContext;
        public UserRepo(AppDbContext appDbContext)
        {
            this.appDbContext = appDbContext;
        }
        public async Task<LoginResponse> LoginUserAsync(LoginDTO loginDTO)
        {
            var getUser = await FindUserByEmailAsync(loginDTO.Email!);
            if (getUser == null) return new LoginResponse(false, "User not found, sorry");

            bool checkPassword = BCrypt.Net.BCrypt.Verify(loginDTO.Password, getUser.Password);
            if (checkPassword)
                return new LoginResponse(true, "Login successfully", GenerateJWTToken(getUser));
            else
                return new LoginResponse(false, "Invalid credentials");
        }

        private string GenerateJWTToken(ApplicationUser getUser)
        {
            // https://www.youtube.com/watch?v=5XZ0zh1_UV0 - 43:17
        }

        private async Task<ApplicationUser> FindUserByEmailAsync(string email) => 
            await appDbContext.Users.FirstOrDefaultAsync(u => u.Email == email);

        public async Task<RegisterationResponse> RegisterUserAsync(RegisterUserDTO registerUserDTO)
        {
            var getUser = await FindUserByEmailAsync(registerUserDTO.Email!);
            if (getUser != null)
                return new RegisterationResponse(false, "User already exist");

            appDbContext.Users.Add(new ApplicationUser()
            {
                Name = registerUserDTO.Name,
                Email = registerUserDTO.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(registerUserDTO.Password)
            });
            await appDbContext.SaveChangesAsync();
            return new RegisterationResponse(true, "Registration completed");
        }
    }
}
