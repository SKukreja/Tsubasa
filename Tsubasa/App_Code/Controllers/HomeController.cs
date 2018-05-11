using Microsoft.AspNet.Identity.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Tsubasa.Models;

/// <summary>
/// Summary description for HomeController
/// </summary>
namespace Tsubasa.Controllers
{
    public class HomeController : Controller
    {
        private ApplicationUserManager _userManager;

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        public ActionResult Default()
        {
            if (Request.IsAuthenticated)
            {
                return RedirectToAction("Home", "Home");
            }
            return View();
        }

        public ActionResult Home()
        {
            ViewData["UserManager"] = UserManager;
            return View();
        }
    }
}