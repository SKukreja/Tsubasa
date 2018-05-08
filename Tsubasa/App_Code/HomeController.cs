using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

/// <summary>
/// Summary description for HomeController
/// </summary>
namespace Tsubasa
{
    public class HomeController : Controller
    {
        public ActionResult Default()
        {
            return View();
        }
    }
}