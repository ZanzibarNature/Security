using System.Net.Http.Headers;
using AuthService.Models;
using AuthService.Service;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly ILogger<AuthenticationController> _logger;
    private readonly KeycloakService _authService = new KeycloakService();

    public AuthenticationController(ILogger<AuthenticationController> logger)
    {
        _logger = logger;
    }

    [HttpGet("external-login/{provider}")]
    public IActionResult ExternalLogin(string provider)
    {
        string url = _authService.GetLoginUrl(provider);
        return Redirect(url);
    }

    [HttpGet("external-callback")]
    public async Task<IActionResult> ExternalCallback(string code)
    {
        if (string.IsNullOrEmpty(code))
        {
            return BadRequest();
        }

        // Exchange authorization code for access token
        var tokenResponse = await _authService.ExchangeCodeForTokenAsync(code);

        if (tokenResponse != null && !string.IsNullOrEmpty(tokenResponse.AccessToken))
        {
            return Ok(tokenResponse);
        }
        else
        {
            return BadRequest();
        }
    }

    [HttpGet("userinfo")]
    public async Task<IActionResult> GetUserInfo()
    {
        if (HttpContext.Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            var accessToken =
                authHeader.ToString().Split(' ')[1];

            Response.ContentType = "application/json";
            try
            {
                User? user = await _authService.GetUserInfo(accessToken);
                return user != null ? Ok(user) : Unauthorized();
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }

        return BadRequest();
    }


    [HttpGet("RefreshToken")]
    public async Task<IActionResult> RefreshAccessTokenAsync()
    {
        // Retrieve the 'refresh_token' header value
        if (HttpContext.Request.Headers.TryGetValue("refresh_token", out var refreshToken))
        {
            // Extract and process the refresh token value
            var refreshTokenValue = refreshToken.ToString();
            try
            {
                Token? token = await _authService.GetRefreshToken(refreshTokenValue);
                return token != null ? Ok(token) : Unauthorized();
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }

        return BadRequest();
    }

    [HttpGet("Logout")]
    public async Task<IActionResult> Logout()
    {
        // Retrieve the 'refresh_token' header value
        if (HttpContext.Request.Headers.TryGetValue("refresh_token", out var refreshToken))
        {
            // Extract and process the refresh token value
            var refreshTokenValue = refreshToken.ToString();
            try
            {
                await _authService.Logout(refreshTokenValue);
                return Ok();
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }

        return BadRequest();
    }
}