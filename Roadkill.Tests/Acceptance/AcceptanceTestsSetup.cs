﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using NUnit.Framework;
using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Firefox;

namespace Roadkill.Tests.Acceptance
{
	[SetUpFixture]
	public class AcceptanceTestsSetup
	{
		public static IWebDriver Driver { get; private set; }
		public static Process IisProcess { get; private set; }

		[SetUp]
		public void BeforeAllTests()
		{
			CopyWebConfig();
			LaunchIisExpress();

			//Driver = new SimpleBrowserDriver();
			//Driver = new FirefoxDriver();
			Driver = new ChromeDriver();
			Driver.Manage().Timeouts().ImplicitlyWait(TimeSpan.FromSeconds(2));
		}

		[TearDown]
		public void AfterAllTests()
		{
			Driver.Dispose();

			if (IisProcess != null)
			{
				IisProcess.CloseMainWindow();
				IisProcess.Dispose();
			}
		}

		public static string GetSitePath()
		{
			string sitePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "Roadkill.Site");
			sitePath = new DirectoryInfo(sitePath).FullName;

			return sitePath;
		}

		private void CopyWebConfig()
		{
			string sitePath = GetSitePath();
			string libFolder = Path.Combine(sitePath, "..", "lib");
			libFolder = new DirectoryInfo(libFolder).FullName;

			string testsWebConfigPath = Path.Combine(libFolder, "Configs", "web.acceptancetests.config");

			// Be a good neighbour and backup the web.config
			string siteWebConfig = Path.Combine(sitePath, "web.config");
			File.Copy(siteWebConfig, siteWebConfig + ".bak", true);
			File.Copy(testsWebConfigPath, siteWebConfig, true);
		}

		private void LaunchIisExpress()
		{
			string sitePath = GetSitePath();
			ProcessStartInfo startInfo = new ProcessStartInfo();
			startInfo.Arguments = string.Format("/path:\"{0}\" /port:{1}", sitePath, 9876);

			string programfiles = programfiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
			string searchPath1 = string.Format(@"{0}\IIS Express\iisexpress.exe", programfiles);
			string searchPath2 = "";
			startInfo.FileName = string.Format(@"{0}\IIS Express\iisexpress.exe", programfiles);

			if (!File.Exists(startInfo.FileName))
			{
				programfiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
				searchPath2 = string.Format(@"{0}\IIS Express\iisexpress.exe", programfiles);
				startInfo.FileName = string.Format(@"{0}\IIS Express\iisexpress.exe", programfiles);
			}

			if (!File.Exists(startInfo.FileName))
			{
				throw new FileNotFoundException(string.Format("IIS Express is not installed in '{0}' or '{1}' and is required for the acceptance tests\n " +
					"Download it from http://www.microsoft.com/en-gb/download/details.aspx?id=1038",
					searchPath1, searchPath2));
			}

			try
			{
				IisProcess = Process.Start(startInfo);
			}
			catch
			{
				IisProcess.CloseMainWindow();
				IisProcess.Dispose();
			}
		}

	}
}
