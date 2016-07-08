using DateFantasy.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace DateFantasy.Controllers
{
    public class HomeController : Controller
    {
        private IDateFantasyRepository _repository;
        //public HomeController()
        //{

        //}
        public HomeController(IDateFantasyRepository repo)
        {
            _repository = repo;
        }

        public ActionResult Index()
        {
            //ViewBag.Title = "Home Page";
            var randomProfiles = _repository.GetRandomProfiles(6);
            
            return View(randomProfiles);          
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";
            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";
            return View();
        }

        public ActionResult Acknowledgements()
        {
            return View();
        }
    }
}
