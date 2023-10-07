using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using API.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController : BaseApiController 
{
    private readonly DataContext _context;
    private readonly ITokenService _tokenService;

    public AccountController(DataContext context, ITokenService tokenService )
    {
        _context = context;
        _tokenService = tokenService;
    }
[HttpPost("register")]
public async Task<ActionResult<UserDto>> Register(RegisterDto registerDTO)
{
    if(await UserExists(registerDTO.Username)) return BadRequest("Username is taken!!");
    using var hmac = new HMACSHA512();

    var user = new AppUser
    {
        UserName = registerDTO.Username.ToLower(),
        PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
        PasswordSalt = hmac.Key
    };

    _context.Users.Add(user);
    await _context.SaveChangesAsync();

    return new UserDto
    {
        Username = user.UserName,
        Token = _tokenService.CreateToken(user)
    };
}

[HttpPost("login")]
public async Task<ActionResult<AppUser>> Login(LoginDto loginDto)
{
    var user = await _context.Users.SingleOrDefaultAsync( x=> x.UserName == loginDto.UserName);
    if (user == null) return Unauthorized("invalid username");

    using var hmac = new HMACSHA512(user.PasswordSalt);
    var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
    for(int i = 0; i < computedHash.Length; i++)
    {
        if(computedHash[i] != user.PasswordHash[i]) return Unauthorized("invalid password");
    }

    return user;
}
private async Task<bool> UserExists( string username)
{
    return await _context.Users.AnyAsync(x=> x.UserName == username.ToLower());
}    

}