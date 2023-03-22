using System.Net.Mime;
using Ardalis.ListStartupServices;
using BlazorAdmin;
using BlazorAdmin.Services;
using Blazored.LocalStorage;
using BlazorShared;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.eShopWeb;
using Microsoft.eShopWeb.ApplicationCore.Interfaces;
using Microsoft.eShopWeb.Infrastructure.Data;
using Microsoft.eShopWeb.Infrastructure.Identity;
using Microsoft.eShopWeb.Web;
using Microsoft.eShopWeb.Web.Configuration;
using Microsoft.eShopWeb.Web.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;


var builder = WebApplication.CreateBuilder(args);

builder.Logging.AddConsole();
builder.Services.AddLogging();
/*builder.Host.UseSerilog((hostingContext, loggerConfiguration) =>
   loggerConfiguration.ReadFrom.Configuration(hostingContext.Configuration)
       .MinimumLevel.Override("Microsoft", LogEventLevel.Error)
       .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Error)
       .MinimumLevel.Override("Serilog", LogEventLevel.Error)
         .Enrich.FromLogContext()//在日志中加入上下文信息，比如时间戳和线程 ID。
        .Enrich.WithClientIp()//在客户端日志中加入IP地址
         .Enrich.WithClientAgent()// 在日志中加入客户端的浏览器代理信息。
       .WriteTo.Console()
 );*/

Microsoft.eShopWeb.Infrastructure.Dependencies.ConfigureServices(builder.Configuration, builder.Services);

builder.Services.AddCookieSettings();//配置cookie 如过期时间,域名,路径等等

/*这段代码是用于配置 ASP.NET Core 应用程序的身份验证方案的，默认身份验证方案是 CookieAuthentication。
它通过调用 AddCookie 方法来配置 Cookie 身份验证方案的行为 当浏览器发送跨站点请求时，
它会判断请求中的 cookie 是否来自当前网站（源），
如果不是，则浏览器会根据 SameSite 属性的设置决定是否发送 cookie。
如果 SameSite 属性的值为 Lax 或 Strict，则浏览器不会发送 cookie，否则会发送。
尽管跨站点不携带 cookie 有助于保护用户安全，但也可能会带来一些问题，比如，
可能需要重新登录以访问先前记录的用户数据和首选项。因此，在设置跨站点 cookie 时应该根据具体情况进行权衡和选择。 */
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
    });

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
           .AddDefaultUI()
           .AddEntityFrameworkStores<AppIdentityDbContext>()//指定AppIdentityDbContext存储身份验证和授权相关数据
                           .AddDefaultTokenProviders();//添加默认的令牌生成和验证器
                           //应用程序的身份验证方案

//向容器中依赖注入一个ITokenClaimsService 生命周期为Scoped的服务
//Scoped 意味着每个请求将创建一个新的实例,并且在请求结束时销毁.
//scoped 瞬时的.
builder.Services.AddScoped<ITokenClaimsService, IdentityTokenClaimService>();

builder.Services.AddCoreServices(builder.Configuration);//自己包装好的
builder.Services.AddWebServices(builder.Configuration);//同上

// Add memory cache services
builder.Services.AddMemoryCache();
builder.Services.AddRouting(options =>
{
    // Replace the type and the name used to refer to it with your own
    // IOutboundParameterTransformer implementation
    options.ConstraintMap["slugify"] = typeof(SlugifyParameterTransformer);
});
builder.Services.AddMvc(options =>
{
    options.Conventions.Add(new RouteTokenTransformerConvention(
             new SlugifyParameterTransformer()));//这个方法会把MyAccount这种名词变成my-account
        /* RouteTokenTransformerConvention路由到具体controller操作方法的类   */

});
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizePage("/Basket/Checkout");
    /* 是指定 "/Basket/Checkout" 页面需要授权才能访问。这意味着用户必须先登录并且具有适当的授权才能访问该页面。
     总体来说，这段代码是为 Razor 页面添加授权规则。当用户尝试访问 "/Basket/Checkout" 页面时，
    系统将检查用户是否已经登录以及是否具有访问该页面的授权。
    如果用户不具备足够的授权，则会被重定向到登录页面或者显示错误信息。*/
});
builder.Services.AddHttpContextAccessor();
builder.Services
    .AddHealthChecks()
    .AddCheck<ApiHealthCheck>("api_health_check", tags: new[] { "apiHealthCheck" })
    .AddCheck<HomePageHealthCheck>("home_page_health_check", tags: new[] { "homePageHealthCheck" });
builder.Services.Configure<ServiceConfig>(config =>
{
    config.Services = new List<ServiceDescriptor>(builder.Services);
    config.Path = "/allservices";
});

// blazor configuration
var configSection = builder.Configuration.GetRequiredSection(BaseUrlConfiguration.CONFIG_NAME);
builder.Services.Configure<BaseUrlConfiguration>(configSection);
var baseUrlConfig = configSection.Get<BaseUrlConfiguration>();

// Blazor Admin Required Services for Prerendering
builder.Services.AddScoped<HttpClient>(s => new HttpClient
{
    BaseAddress = new Uri(baseUrlConfig.WebBase)
});

// add blazor services
builder.Services.AddBlazoredLocalStorage();
builder.Services.AddServerSideBlazor();
builder.Services.AddScoped<ToastService>();
builder.Services.AddScoped<HttpService>();
builder.Services.AddBlazorServices();

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

var app = builder.Build();

app.Logger.LogInformation("App created...");

app.Logger.LogInformation("Seeding Database...");

using (var scope = app.Services.CreateScope())
{
    var scopedProvider = scope.ServiceProvider;
    try
    {
        var catalogContext = scopedProvider.GetRequiredService<CatalogContext>();
        await CatalogContextSeed.SeedAsync(catalogContext, app.Logger);

        var userManager = scopedProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scopedProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var identityContext = scopedProvider.GetRequiredService<AppIdentityDbContext>();
        await AppIdentityDbContextSeed.SeedAsync(identityContext, userManager, roleManager);
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "An error occurred seeding the DB.");
    }
}

var catalogBaseUrl = builder.Configuration.GetValue(typeof(string), "CatalogBaseUrl") as string;
if (!string.IsNullOrEmpty(catalogBaseUrl))
{
    app.Use((context, next) =>
    {
        context.Request.PathBase = new PathString(catalogBaseUrl);
        return next();
    });
}

app.UseHealthChecks("/health",
    new HealthCheckOptions
    {
        ResponseWriter = async (context, report) =>
        {
            var result = new
            {
                status = report.Status.ToString(),
                errors = report.Entries.Select(e => new
                {
                    key = e.Key,
                    value = Enum.GetName(typeof(HealthStatus), e.Value.Status)
                })
            }.ToJson();
            context.Response.ContentType = MediaTypeNames.Application.Json;
            await context.Response.WriteAsync(result);
        }
    });
if (app.Environment.IsDevelopment() || app.Environment.EnvironmentName == "Docker")
{
    app.Logger.LogInformation("Adding Development middleware...");
    app.UseDeveloperExceptionPage();
    app.UseShowAllServicesMiddleware();
    app.UseMigrationsEndPoint();
    app.UseWebAssemblyDebugging();
}
else
{
    app.Logger.LogInformation("Adding non-Development middleware...");
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseBlazorFrameworkFiles();
app.UseStaticFiles();
app.UseRouting();

app.UseCookiePolicy();
app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllerRoute("default", "{controller:slugify=Home}/{action:slugify=Index}/{id?}");
    endpoints.MapRazorPages();
    endpoints.MapHealthChecks("home_page_health_check", new HealthCheckOptions { Predicate = check => check.Tags.Contains("homePageHealthCheck") });
    endpoints.MapHealthChecks("api_health_check", new HealthCheckOptions { Predicate = check => check.Tags.Contains("apiHealthCheck") });
    //endpoints.MapBlazorHub("/admin");
    endpoints.MapFallbackToFile("index.html");
});

app.Logger.LogInformation("LAUNCHING");
app.Run();
