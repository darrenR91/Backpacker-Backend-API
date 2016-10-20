using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.ModelBinding;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using The88Days.Models;
using The88Days.Providers;
using The88Days.Results;
using Newtonsoft.Json.Linq;
using Microsoft.Owin.Security.Facebook;
using System.Linq;

namespace The88Days.Controllers
{
    //[Authorize]
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {
        private ApplicationDbContext db = new ApplicationDbContext();
        private const string LocalLoginProvider = "Local";
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager,
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat)
        {
            UserManager = userManager;
            AccessTokenFormat = accessTokenFormat;
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        // GET api/Account/UserInfo
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("UserInfo")]
        public UserInfoViewModel GetUserInfo()
        {
            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            return new UserInfoViewModel
            {
                Email = User.Identity.GetUserName(),
                HasRegistered = externalLogin == null,
                LoginProvider = externalLogin != null ? externalLogin.LoginProvider : null
            };
        }

        // POST api/Account/Logout
        [Route("Logout")]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }

        // GET api/Account/ManageInfo?returnUrl=%2F&generateState=true
        [Route("ManageInfo")]
        public async Task<ManageInfoViewModel> GetManageInfo(string returnUrl, bool generateState = false)
        {
            IdentityUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            if (user == null)
            {
                return null;
            }

            List<UserLoginInfoViewModel> logins = new List<UserLoginInfoViewModel>();

            foreach (IdentityUserLogin linkedAccount in user.Logins)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = linkedAccount.LoginProvider,
                    ProviderKey = linkedAccount.ProviderKey
                });
            }

            if (user.PasswordHash != null)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = LocalLoginProvider,
                    ProviderKey = user.UserName,
                });
            }

            return new ManageInfoViewModel
            {
                LocalLoginProvider = LocalLoginProvider,
                Email = user.UserName,
                Logins = logins,
                ExternalLoginProviders = GetExternalLogins(returnUrl, generateState)
            };
        }

        // POST api/Account/ChangePassword
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);
            
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/SetPassword
        [Route("SetPassword")]
        public async Task<IHttpActionResult> SetPassword(SetPasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/AddExternalLogin
        [Route("AddExternalLogin")]
        public async Task<IHttpActionResult> AddExternalLogin(AddExternalLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

            AuthenticationTicket ticket = AccessTokenFormat.Unprotect(model.ExternalAccessToken);

            if (ticket == null || ticket.Identity == null || (ticket.Properties != null
                && ticket.Properties.ExpiresUtc.HasValue
                && ticket.Properties.ExpiresUtc.Value < DateTimeOffset.UtcNow))
            {
                return BadRequest("External login failure.");
            }

            ExternalLoginData externalData = ExternalLoginData.FromIdentity(ticket.Identity);

            if (externalData == null)
            {
                return BadRequest("The external login is already associated with an account.");
            }

            IdentityResult result = await UserManager.AddLoginAsync(User.Identity.GetUserId(),
                new UserLoginInfo(externalData.LoginProvider, externalData.ProviderKey));

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/RemoveLogin
        [Route("RemoveLogin")]
        public async Task<IHttpActionResult> RemoveLogin(RemoveLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result;

            if (model.LoginProvider == LocalLoginProvider)
            {
                result = await UserManager.RemovePasswordAsync(User.Identity.GetUserId());
            }
            else
            {
                result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(),
                    new UserLoginInfo(model.LoginProvider, model.ProviderKey));
            }

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogin
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {
            if (error != null)
            {
                return Redirect(Url.Content("~/") + "#error=" + Uri.EscapeDataString(error));
            }

            if (!User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider,
                externalLogin.ProviderKey));
            
            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                
                 ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    OAuthDefaults.AuthenticationType);
                ClaimsIdentity cookieIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    CookieAuthenticationDefaults.AuthenticationType);

                AuthenticationProperties properties = ApplicationOAuthProvider.CreateProperties(user.UserName);
                Authentication.SignIn(properties, oAuthIdentity, cookieIdentity);
            }
            else
            {
                IEnumerable<Claim> claims = externalLogin.GetClaims();
                ClaimsIdentity identity = new ClaimsIdentity(claims, OAuthDefaults.AuthenticationType);
                Authentication.SignIn(identity);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogins?returnUrl=%2F&generateState=true
        [AllowAnonymous]
        [Route("ExternalLogins")]
        public IEnumerable<ExternalLoginViewModel> GetExternalLogins(string returnUrl, bool generateState = false)
        {
            IEnumerable<AuthenticationDescription> descriptions = Authentication.GetExternalAuthenticationTypes();
            List<ExternalLoginViewModel> logins = new List<ExternalLoginViewModel>();

            string state;

            if (generateState)
            {
                const int strengthInBits = 256;
                state = RandomOAuthStateGenerator.Generate(strengthInBits);
            }
            else
            {
                state = null;
            }

            foreach (AuthenticationDescription description in descriptions)
            {
                ExternalLoginViewModel login = new ExternalLoginViewModel
                {
                    Name = description.Caption,
                    Url = Url.Route("ExternalLogin", new
                    {
                        provider = description.AuthenticationType,
                        response_type = "token",
                        client_id = Startup.PublicClientId,
                        redirect_uri = new Uri(Request.RequestUri, returnUrl).AbsoluteUri,
                        state = state
                    }),
                    State = state
                };
                logins.Add(login);
            }

            return logins;
        }

        // POST api/Account/Register
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(RegisterBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser() { UserName = model.UserName, Email = model.Email, Nationality=model.Nationality, WorkStatus=model.WorkStatus };

            IdentityResult result = await UserManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/RegisterExternal
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("RegisterExternal")]
        public async Task<IHttpActionResult> RegisterExternal(RegisterExternalBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var info = await Authentication.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return InternalServerError();
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            result = await UserManager.AddLoginAsync(user.Id, info.Login);
            if (!result.Succeeded)
            {
                return GetErrorResult(result); 
            }
            return Ok();
        }
        // POST api/Account/LocalLogin
        [OverrideAuthentication]
        [AllowAnonymous]
        [Route("LocalLogin")]
        public async Task<IHttpActionResult> LocalLogin(Login model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            ApplicationUser user = await UserManager.FindAsync(model.UserName, model.Password);
            if(user==null)
            {
                return BadRequest("The user name or password is incorrect.");
            }
            

                //authenticate
                var identity = await UserManager.CreateIdentityAsync(user, OAuthDefaults.AuthenticationType);
                //IEnumerable<Claim> claims = externalLogin.GetClaims();
                //identity.AddClaims(claims);
                Authentication.SignIn(identity);

                ClaimsIdentity oAuthIdentity = new ClaimsIdentity(Startup.OAuthOptions.AuthenticationType);

                oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
                oAuthIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));

                AuthenticationTicket ticket = new AuthenticationTicket(oAuthIdentity, new AuthenticationProperties());

                DateTime currentUtc = DateTime.UtcNow;
                ticket.Properties.IssuedUtc = currentUtc;
                ticket.Properties.ExpiresUtc = currentUtc.Add(Startup.OAuthOptions.AccessTokenExpireTimeSpan);

                string accessToken = Startup.OAuthOptions.AccessTokenFormat.Protect(ticket);



                Microsoft.Owin.Security.Infrastructure.AuthenticationTokenCreateContext context =
                        new Microsoft.Owin.Security.Infrastructure.AuthenticationTokenCreateContext(
                            Request.GetOwinContext(),
                            Startup.OAuthOptions.AccessTokenFormat, ticket);

                await Startup.OAuthOptions.RefreshTokenProvider.CreateAsync(context);
                // properties.Dictionary.Add("refresh_token", context.Token); original 2
                ticket.Properties.Dictionary.Add("UserName", user.UserName);

                Request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken); ///already there in solution



                // Create the response building a JSON object that mimics exactly the one issued by the default /Token endpoint
                JObject token = new JObject(
                new JProperty("userName", user.UserName),
                new JProperty("nationality", user.Nationality),
                new JProperty("workStatus", user.WorkStatus),
                new JProperty("userId", user.Id),
                new JProperty("profilePhoto", user.ProfilePicture),
                new JProperty("access_token", accessToken),
                new JProperty("token_type", "bearer"),
                new JProperty("refresh_token", context.Token),
                new JProperty("expires_in", Startup.OAuthOptions.AccessTokenExpireTimeSpan.TotalSeconds.ToString()),
                new JProperty("issued", currentUtc.ToString("ddd, dd MMM yyyy HH':'mm':'ss 'GMT'")),
                new JProperty("expires", currentUtc.Add(Startup.OAuthOptions.AccessTokenExpireTimeSpan).ToString("ddd, dd MMM yyyy HH:mm:ss 'GMT'"))
                );

                return Ok(token);
          
        }
    ////////////////////////////////////////////   facebook login    //////////////////////////////////////////////////////////////////////
    /////CODETRIX STUDIO///////////////
    // POST api/Account/RegisterExternalToken
    [OverrideAuthentication]
        [AllowAnonymous]
        [Route("RegisterExternalToken")]
        public async Task<IHttpActionResult> RegisterExternalToken(RegisterExternalTokenBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            //validate token
            ExternalLoginData externalLogin = await ExternalLoginData.FromToken(model.Provider, model.Token);

            bool alreadyRegistered=false;

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != model.Provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return InternalServerError();
            }
            //if we reached this point then token is valid
            // Original from tutorial >>>>> ApplicationUser user = await UserManager.FindByEmailAsync(model.Email);

            ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider, externalLogin.ProviderKey));
            bool hasRegistered = user != null;
            
            IdentityResult result;

            if (!hasRegistered)
            {

                var info = new UserLoginInfo(externalLogin.LoginProvider, externalLogin.ProviderKey);

                user = new ApplicationUser() { UserName = model.UserName, Email =model.Email ,Nationality=model.Nationality,
                WorkStatus=model.WorkStatus};//externalLogin.ProviderKey+"@newAccountByFacebook" };

                result = await UserManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    return GetErrorResult(result);
                }

                result = await UserManager.AddLoginAsync(user.Id, info);
                if (!result.Succeeded)
                {
                    return GetErrorResult(result);
                }
            }
            else
            {
                alreadyRegistered = true;
            }

            //authenticate
            var identity = await UserManager.CreateIdentityAsync(user, OAuthDefaults.AuthenticationType);
            IEnumerable<Claim> claims = externalLogin.GetClaims();
            identity.AddClaims(claims);
            Authentication.SignIn(identity);

            ClaimsIdentity oAuthIdentity = new ClaimsIdentity(Startup.OAuthOptions.AuthenticationType);

            oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
            oAuthIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));

            AuthenticationTicket ticket = new AuthenticationTicket(oAuthIdentity, new AuthenticationProperties());

            DateTime currentUtc = DateTime.UtcNow;
            ticket.Properties.IssuedUtc = currentUtc;
            ticket.Properties.ExpiresUtc = currentUtc.Add(Startup.OAuthOptions.AccessTokenExpireTimeSpan);

            string accessToken = Startup.OAuthOptions.AccessTokenFormat.Protect(ticket);



            Microsoft.Owin.Security.Infrastructure.AuthenticationTokenCreateContext context =
                    new Microsoft.Owin.Security.Infrastructure.AuthenticationTokenCreateContext(
                        Request.GetOwinContext(),
                        Startup.OAuthOptions.AccessTokenFormat, ticket);

            await Startup.OAuthOptions.RefreshTokenProvider.CreateAsync(context);
           // properties.Dictionary.Add("refresh_token", context.Token); original 2
            ticket.Properties.Dictionary.Add("UserName", user.UserName);

            Request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken); ///already there in solution



            // Create the response building a JSON object that mimics exactly the one issued by the default /Token endpoint
            JObject token = new JObject(
            new JProperty("userName", user.UserName),
            new JProperty("userId", user.Id),
            new JProperty("profilePhoto", user.ProfilePicture),
            new JProperty("access_token", accessToken),
            new JProperty("token_type", "bearer"),
            new JProperty("refresh_token", context.Token),
            new JProperty("expires_in", Startup.OAuthOptions.AccessTokenExpireTimeSpan.TotalSeconds.ToString()),
            new JProperty("issued", currentUtc.ToString("ddd, dd MMM yyyy HH':'mm':'ss 'GMT'")),
            new JProperty("expires", currentUtc.Add(Startup.OAuthOptions.AccessTokenExpireTimeSpan).ToString("ddd, dd MMM yyyy HH:mm:ss 'GMT'"))
            );

            return Ok(token);
        }
        // POST api/Account/CheckForExistingAccount
        [OverrideAuthentication]
        [AllowAnonymous]
        [Route("CheckForExistingAccount")]
        public async Task<IHttpActionResult> CheckForExistingAccount(RegisterExternalTokenBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            //validate token
            ExternalLoginData externalLogin = await ExternalLoginData.FromToken(model.Provider, model.Token);
            

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != model.Provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return InternalServerError();
            }
            //if we reached this point then token is valid
            // Original from tutorial >>>>> ApplicationUser user = await UserManager.FindByEmailAsync(model.Email);

            ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider, externalLogin.ProviderKey));
            bool hasRegistered = user != null;


            if (hasRegistered)
            {


                //authenticate
                var identity = await UserManager.CreateIdentityAsync(user, OAuthDefaults.AuthenticationType);
                IEnumerable<Claim> claims = externalLogin.GetClaims();
                identity.AddClaims(claims);
                Authentication.SignIn(identity);

                ClaimsIdentity oAuthIdentity = new ClaimsIdentity(Startup.OAuthOptions.AuthenticationType);

                oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
                oAuthIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));

                AuthenticationTicket ticket = new AuthenticationTicket(oAuthIdentity, new AuthenticationProperties());

                DateTime currentUtc = DateTime.UtcNow;
                ticket.Properties.IssuedUtc = currentUtc;
                ticket.Properties.ExpiresUtc = currentUtc.Add(Startup.OAuthOptions.AccessTokenExpireTimeSpan);

                string accessToken = Startup.OAuthOptions.AccessTokenFormat.Protect(ticket);



                Microsoft.Owin.Security.Infrastructure.AuthenticationTokenCreateContext context =
                        new Microsoft.Owin.Security.Infrastructure.AuthenticationTokenCreateContext(
                            Request.GetOwinContext(),
                            Startup.OAuthOptions.AccessTokenFormat, ticket);

                await Startup.OAuthOptions.RefreshTokenProvider.CreateAsync(context);
                // properties.Dictionary.Add("refresh_token", context.Token); original 2
                ticket.Properties.Dictionary.Add("UserName", user.UserName);

                Request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken); ///already there in solution



                // Create the response building a JSON object that mimics exactly the one issued by the default /Token endpoint
                JObject token = new JObject(
                new JProperty("userName", user.UserName),
                new JProperty("nationality", user.Nationality),
                new JProperty("workStatus", user.WorkStatus),
                new JProperty("userId", user.Id),
                new JProperty("profilePhoto", user.ProfilePicture),
                new JProperty("access_token", accessToken),
                new JProperty("token_type", "bearer"),
                new JProperty("refresh_token", context.Token),
                new JProperty("expires_in", Startup.OAuthOptions.AccessTokenExpireTimeSpan.TotalSeconds.ToString()),
                new JProperty("issued", currentUtc.ToString("ddd, dd MMM yyyy HH':'mm':'ss 'GMT'")),
                new JProperty("expires", currentUtc.Add(Startup.OAuthOptions.AccessTokenExpireTimeSpan).ToString("ddd, dd MMM yyyy HH:mm:ss 'GMT'"))
                );

                return Ok(token);
            }
            else
            {
                JObject token1 = new JObject(
                new JProperty("userName", "Not Registered")
                );

                return Ok(token1);
            }
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }
        // GET api/Account/AllUsers
        [Authorize]
        [Route("AllUsers")]
        public List<UserSearchDetails> GetAllUsers()
        {
            var userList = new List<UserSearchDetails>();
            foreach (var user in db.Users)
            {
                if (!user.UserName.Equals(User.Identity.GetUserName() ) & user.Privacy.Equals(false))
                {

                    var model = new UserSearchDetails()
                    {
                        userName = user.UserName,
                        nationality = user.Nationality,
                        workStatus = user.WorkStatus,
                        along = user.Long,
                        lat = user.Lat,
                        profilePhoto = "https://pbs.twimg.com/profile_images/1925075223/kangaroo_.jpg"//user.ProfilePicture

                    };
                    userList.Add(model);

                }
            }
            return userList;
        }
        // Get api/Account/GetAllUsersByDistance/radius
        [Authorize]
        [Route("GetAllUsersByDistance")]
        public List<UserSearchDetails> GetAllUsersByDistance(int Radius)
        {

            ApplicationUser user = UserManager.FindById(User.Identity.GetUserId());

            var context = new ApplicationDbContext();
            
            return HelperClass.GetBackpackersByDistance(db, user.Lat, user.Long, user.UserName, Radius);
        }
        // GET api/Account/GetAllUsersByDistanceMethodTwo
        [Authorize]
        [Route("GetAllUsersByDistanceMethodTwo")]
        public List<UserSearchDetails> GetAllUsersByDistanceMethodTwo()
        {

            ApplicationUser user = UserManager.FindById(User.Identity.GetUserId());

            var context = new ApplicationDbContext();

            var allUsers = context.Users.ToList();


            return HelperClass.GetByDistanceMethodTwo(db, user.Lat, user.Long, user.UserName);
        }
        // GET api/Account/GetAllUsersByDistanceMethodThree
        [Authorize]
        [Route("GetAllUsersByDistanceMethodThree")]
        public List<UserSearchDetails> GetAllUsersByDistanceMethodThree()
        {

            ApplicationUser user = UserManager.FindById(User.Identity.GetUserId());

            var context = new ApplicationDbContext();

            var allUsers = context.Users.ToList();


            return HelperClass.GetByDistanceMethodThree(db, user.Lat, user.Long, user.UserName);
        }
        // POST api/Account/AndroidUpdateRegister
        [Authorize]
        [Route("AndroidUpdateRegister")]
        public async Task<IHttpActionResult> AndroidUpdateRegister(UpdateUser model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            ApplicationUser user = UserManager.FindById(User.Identity.GetUserId());

            if (model.Nationality != null)
            {
                user.Nationality = model.Nationality;
            }
            //if (model.Privacy.)
            //{
                user.Privacy = model.Privacy;
            //}
            if (model.WorkStatus != null)
            {
                user.WorkStatus = model.WorkStatus;
            }
            if (model.GcmRegId != null)
            {
                user.GcmRegId = model.GcmRegId;
            }
            if (model.Email != null)
            {
                user.Email = model.Email;
            }
            if (model.UserName != null)
            {
                user.UserName = model.UserName;
            }
            user.ProfilePicture = "https://the88daysblob.blob.core.windows.net/profilephotos/" + user.Id;

            if (!model.Long.Equals(0) & !model.Lat.Equals(0))
            {
                user.Location = HelperClass.CreatePoint(model.Lat, model.Long);
                user.Lat = model.Lat;
                user.Long = model.Long;
            }

            //var context = new ApplicationDbContext();
            IdentityResult result = await UserManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }
            //context.SaveChanges();
            return Ok();
        }
        
        #region Helpers
        //public static FacebookAuthenticationOptions facebookAuthOptions { get; private set; }

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }

            public IList<Claim> GetClaims()
            {
                IList<Claim> claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, ProviderKey, null, LoginProvider));

                if (UserName != null)
                {
                    claims.Add(new Claim(ClaimTypes.Name, UserName, null, LoginProvider));
                }

                return claims;
            }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer)
                    || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name)
                };
            }
            ///////// ADDED for facebook
            public static async Task<ExternalLoginData> FromToken(string provider, string accessToken)
            {
                string UserName = "";
                string verifyTokenEndPoint = "", verifyAppEndpoint = "";
                HttpClient client = new HttpClient();

                if (provider == "Facebook")
                {
                    verifyTokenEndPoint = string.Format("https://graph.facebook.com/me?access_token={0}", accessToken);
                    verifyAppEndpoint = string.Format("https://graph.facebook.com/app?access_token={0}", accessToken);
                }
                else if (provider == "Google")
                {
                    // not implemented yet
                    return null;
                    //verifyTokenEndPoint = string.Format("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={0}", accessToken);
                }
                else if (provider == "Twitter")
                {
                    verifyTokenEndPoint = string.Format("https://api.twitter.com/1.1/account/verify_credentials.json");
                    // don't need verifyAppEndPoint as our twitter app automatically gets verified. The token will be invalid if it was issues by some other spoofing app.
                    //add authorization headers here...
                    //client.DefaultRequestHeaders.Add("Authorization", string.Format("your authorizations here&access_Token={0}&other stuff", accessToken));
                    return null; // remove return on implementation.
                }
                else
                {
                    return null;
                }

                Uri uri = new Uri(verifyTokenEndPoint);
                HttpResponseMessage response = await client.GetAsync(uri);
                ClaimsIdentity identity = null;

                if (response.IsSuccessStatusCode)
                {
                    string content = await response.Content.ReadAsStringAsync();
                    dynamic iObj = (Newtonsoft.Json.Linq.JObject)Newtonsoft.Json.JsonConvert.DeserializeObject(content);


                    identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);

                    if (provider == "Facebook")
                    {
                        uri = new Uri(verifyAppEndpoint);
                        response = await client.GetAsync(uri);
                        content = await response.Content.ReadAsStringAsync();
                        dynamic appObj = (Newtonsoft.Json.Linq.JObject)Newtonsoft.Json.JsonConvert.DeserializeObject(content);
                        if (appObj["id"] != "223865401279451")
                        {
                            return null;
                        }
                        UserName = iObj["name"];
                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, iObj["id"].ToString(), ClaimValueTypes.String, "Facebook", "Facebook"));

                    }
                    else if (provider == "Google")
                    {
                        //not implemented yet
                    }
                    else if (provider == "Twitter")
                    {
                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, iObj["id"].ToString(), ClaimValueTypes.String, "Twitter", "Twitter"));
                    }
                }

                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer) || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }
                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = UserName // identity.FindFirstValue(ClaimTypes.Name)
                };
            }
            ///////// end added for facebook //////////
        }

        private static class RandomOAuthStateGenerator
        {
            private static RandomNumberGenerator _random = new RNGCryptoServiceProvider();

            public static string Generate(int strengthInBits)
            {
                const int bitsPerByte = 8;

                if (strengthInBits % bitsPerByte != 0)
                {
                    throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
                }

                int strengthInBytes = strengthInBits / bitsPerByte;

                byte[] data = new byte[strengthInBytes];
                _random.GetBytes(data);
                return HttpServerUtility.UrlTokenEncode(data);
            }
        }

        #endregion
    }
}
