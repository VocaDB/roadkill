﻿using System;
using System.Configuration;
using System.Data.SqlClient;
using System.IO;
using System.Net.Mail;
using System.Reflection;
using NUnit.Framework;
using OpenQA.Selenium;

namespace Roadkill.Tests.Acceptance
{
	/// <summary>
	/// The base class for all Acceptance tests
	/// </summary>
	[Category("Acceptance")]
	public abstract class AcceptanceTestBase
	{
		public static readonly string ADMIN_EMAIL = Settings.ADMIN_EMAIL;
		public static readonly string ADMIN_PASSWORD = Settings.ADMIN_PASSWORD;

		protected static readonly string EDITOR_EMAIL = Settings.EDITOR_EMAIL;
		protected static readonly string EDITOR_PASSWORD = Settings.EDITOR_PASSWORD;

		protected IWebDriver Driver;
		protected string LoginUrl;
		protected string BaseUrl;
		protected string LogoutUrl;
		protected bool IsWindowsAuthTests;

		[SetUp]
		public void Setup()
		{
			string url = ConfigurationManager.AppSettings["url"];
			if (string.IsNullOrEmpty(url))
				url = "http://localhost:9876";

			Console.WriteLine("============ Acceptance tests setup ============");

			SqlExpressSetup.RecreateLocalDbData();
			ConfigFileManager.CopyRoadkillConfig();

			BaseUrl = url;
			LoginUrl = BaseUrl + "/user/login";
			LogoutUrl = BaseUrl + "/user/logout";
			Driver = AcceptanceTestsSetup.Driver;
			IsWindowsAuthTests = (ConfigurationManager.AppSettings["useWindowsAuth"] == "true");

			Console.WriteLine("=================================================");
		}

		protected void CreatePageWithTags(params string[] tags)
		{
			CreatePageWithTitleAndTags("My title", tags);
		}

		protected void CreatePageWithTitleAndTags(string title, params string[] tags)
		{
			Driver.FindElement(By.CssSelector("a[href='/pages/new']")).Click();
			Driver.FindElement(By.Name("Title")).SendKeys(title);

			foreach (string tag in tags)
			{
				Driver.FindElement(By.Name("TagsEntry")).SendKeys(tag);
				Driver.FindElement(By.Name("TagsEntry")).SendKeys(Keys.Space);
			}

			Driver.FindElement(By.Name("Content")).SendKeys("Some content goes here");
			Driver.FindElement(By.CssSelector("input[type=submit]")).Click();
		}

		protected void LoginAsAdmin()
		{
			if (IsWindowsAuthTests)
			{
				Driver.Navigate().GoToUrl(BaseUrl);
				return;
			}

			Driver.Navigate().GoToUrl(LoginUrl);
			Driver.FindElement(By.Name("email")).SendKeys(ADMIN_EMAIL);
			Driver.FindElement(By.Name("password")).SendKeys(ADMIN_PASSWORD);
			Driver.FindElement(By.CssSelector("input[type=submit]")).Click();
		}

		protected void LoginAsEditor()
		{
			if (IsWindowsAuthTests)
			{
				Driver.Navigate().GoToUrl(BaseUrl);
				return;
			}

			Driver.Navigate().GoToUrl(LoginUrl);
			Driver.FindElement(By.Name("email")).SendKeys(EDITOR_EMAIL);
			Driver.FindElement(By.Name("password")).SendKeys(EDITOR_PASSWORD);
			Driver.FindElement(By.CssSelector("input[type=submit]")).Click();
		}

		protected void Logout()
		{
			if (IsWindowsAuthTests)
			{
				Driver.Navigate().GoToUrl(BaseUrl);
				return;
			}

			Driver.Navigate().GoToUrl(LogoutUrl);
		}
	}
}
