using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;
[Authorize] 
public class UsersController : BaseApiController
{
    private readonly DataContext _context;
    private readonly IUserRepository _userRepository;
    private readonly IMapper _mapper;

    public UsersController(DataContext context )
    {
        _context = context;
    }

    public UsersController(IUserRepository userRepository, IMapper mapper)
    {
        _userRepository = userRepository;
        _mapper = mapper;
    }
    [HttpGet]
     public async Task<ActionResult<IEnumerable<AppUser>>> GetUsers()
     {
        var users = await _userRepository.GetMembersAsync();
        return Ok(users);
     }

     [HttpGet("{id}")]
     public async Task<ActionResult<MemberDto>> GetUsers(string username)
     { 
        return await _userRepository.GetMemberAsync(username); 
       
     }
}
