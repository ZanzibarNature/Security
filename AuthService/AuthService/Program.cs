using System.Net;
using Prometheus;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Any, 8080);    
});


var app = builder.Build();
app.UseMetricServer();
app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpMetrics(options=>
{
    options.AddCustomLabel("host", context => context.Request.Host.Host);
});

app.UseAuthentication();

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();