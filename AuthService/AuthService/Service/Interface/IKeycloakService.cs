namespace AuthService.service.Interface;
using Models;


public interface IKeycloakService
{
    public string GetLoginUrl(string provider);
    public Task<User> GetUserInfo(string accessToken);
    public Task<Token> RefreshToken(string refreshToken);
    public Task<Token> ExchangeCodeForTokenAsync(string code);
    public Task<string> Logout(string refreshToken);
}