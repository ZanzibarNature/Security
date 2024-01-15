using AuthService.Models;
using AuthService.Service;
using AuthService.service.Interface;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly ILogger<AuthenticationController> _logger;
    private readonly IKeycloakService _authService = new KeycloakService();

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
        return BadRequest();
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
                Token? token = await _authService.RefreshToken(refreshTokenValue);
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
                var reponse = await _authService.Logout(refreshTokenValue);
                return reponse != null ? Ok() : BadRequest();
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }

        return BadRequest();
    }
}