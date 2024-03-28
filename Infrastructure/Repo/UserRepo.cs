using Application.Contracts;
using Application.DTOs;
using Domain.Entities;
using Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Infrastructure.Repo
{
    internal class UserRepo : IUser
    {
        private readonly AppDbContext appDbContext;
        private readonly IConfiguration configuration;

        public UserRepo(AppDbContext appDbContext, IConfiguration configuration)
        {
            this.appDbContext = appDbContext;
            this.configuration = configuration;
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

        private string GenerateJWTToken(ApplicationUser user)
        {
            // https://www.youtube.com/watch?v=5XZ0zh1_UV0 - 43:17
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!));
            var credential = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Name!),
                new Claim(ClaimTypes.Email, user.Email!),
            };
            var token = new JwtSecurityToken(
                issuer: configuration["Jwt:Issuer"],
                audience: configuration["Jwt:Audience"],
                claims: userClaims,
                expires: DateTime.Now.AddDays(5),
                signingCredentials: credential
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
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
