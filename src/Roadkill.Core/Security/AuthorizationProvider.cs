using System;
using System.Security.Principal;
using System.Web;
using Roadkill.Core.Configuration;

namespace Roadkill.Core.Security
{
	public class AuthorizationProvider : IAuthorizationProvider
	{
		private readonly ApplicationSettings _applicationSettings;
		private readonly UserServiceBase _userService;

		public AuthorizationProvider(ApplicationSettings applicationSettings, UserServiceBase userService)
		{
			if (applicationSettings == null)
				throw new ArgumentNullException("applicationSettings");

			if (userService == null)
				throw new ArgumentNullException("userService");

			_applicationSettings = applicationSettings;
			_userService = userService;
		}

		public virtual bool IsAdmin(IPrincipal principal)
		{
			var name = _userService.GetLoggedInUserName(new HttpContextWrapper(HttpContext.Current));

			// For custom IIdentity implementations, check the name (for Windows this should never happen)
			if (string.IsNullOrEmpty(name))
				return false;

			if (_userService.IsAdmin(name))
				return true;
			else
				return false;
		}

		public virtual bool IsEditor(IPrincipal principal)
		{
			var name = _userService.GetLoggedInUserName(new HttpContextWrapper(HttpContext.Current));

			// Same as IsAdmin - for custom IIdentity implementations, check the name (for Windows this should never happen)
			if (string.IsNullOrEmpty(name))
				return false;

			if (_userService.IsAdmin(name) || _userService.IsEditor(name))
				return true;
			else
				return false;
		}

		public virtual bool IsViewer(IPrincipal principal)
		{
			return true;
		}
	}
}
