namespace AuthServiceTest;

public class KeycloakServiceTest
{
    public class KeycloakServiceTests
    {
        private readonly Mock<IKeycloakService> _mockKeycloakService;

        public KeycloakServiceTests()
        {
            _mockKeycloakService = new Mock<IKeycloakService>();
        }

        [Fact]
        public void GetLoginUrl_ReturnsValidUrl()
        {
            var keycloakService = new KeycloakService();

            var loginUrl = keycloakService.GetLoginUrl("google");

            Assert.NotNull(loginUrl);
        }

        [Fact]
        public async Task GetUserInfo_ValidAccessToken_ReturnsUser()
        {
            var expectedUser = new User { email_verified = "true", roles = new[] { "user" }, given_name = "John", family_name = "Doe", email = "john@gmail.com"};
            var accessToken = "validAccessToken";
            _mockKeycloakService.Setup(x => x.GetUserInfo(accessToken)).ReturnsAsync(expectedUser);

            var actualUser = await _mockKeycloakService.Object.GetUserInfo(accessToken);

            Assert.NotNull(actualUser);
        }

        [Fact]
        public async Task RefreshToken_ValidRefreshToken_ReturnsToken()
        {
            var expectedToken = new Token { AccessToken = "asdmkajsdmkjm", ExpiresIn = 1200, RefreshToken = "asdasdasdasd", TokenType = "Bearer"};
            var refreshToken = "validRefreshToken";
            _mockKeycloakService.Setup(x => x.RefreshToken(refreshToken)).ReturnsAsync(expectedToken);

            var actualToken = await _mockKeycloakService.Object.RefreshToken(refreshToken);

            Assert.NotNull(actualToken);
        }

        [Fact]
        public async Task ExchangeCodeForTokenAsync_ValidCode_ReturnsToken()
        {
            var expectedToken = new Token { AccessToken = "asdmkajsdmkjm", ExpiresIn = 1200, RefreshToken = "asdasdasdasd", TokenType = "Bearer"};
            var code = "validCode";
            _mockKeycloakService.Setup(x => x.ExchangeCodeForTokenAsync(code)).ReturnsAsync(expectedToken);

            var actualToken = await _mockKeycloakService.Object.ExchangeCodeForTokenAsync(code);

            Assert.NotNull(actualToken);
        }

        [Fact]
        public async Task Logout_ValidRefreshToken_ReturnsResponse()
        {
            var expectedResponse = "Logout Successful";
            var refreshToken = "validRefreshToken";
            _mockKeycloakService.Setup(x => x.Logout(refreshToken)).ReturnsAsync(expectedResponse);

            var actualResponse = await _mockKeycloakService.Object.Logout(refreshToken);

            Assert.NotNull(actualResponse);
        }
    }
}