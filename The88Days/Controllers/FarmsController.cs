using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Core;
using System.Data.Entity.Infrastructure;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Description;
using The88Days.Models;

namespace The88Days.Controllers
{
    [Authorize]
    [RoutePrefix("api/Farms")]
    public class FarmController : ApiController
    {
        private ApplicationDbContext db = new ApplicationDbContext();

        // GET: api/Farms
        public IQueryable<Farm> GetFarms()
        {
            return db.Farms;
        }

        // GET: api/Farms/5
        [ResponseType(typeof(Farm))]
        public async Task<IHttpActionResult> GetFarm(int id)
        {
            Farm farm = await db.Farms.FindAsync(id);
            if (farm == null)
            {
                return NotFound();
            }

            return Ok(farm);
        }

        // PUT: api/Farms/5
        [ResponseType(typeof(void))]
        public async Task<IHttpActionResult> PutFarm(int id, Farm farm)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != farm.FarmId)
            {
                return BadRequest();
            }

            db.Entry(farm).State = EntityState.Modified;

            try
            {
                await db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!FarmExists(farm.Name))
                {
                    return BadRequest();
                }
                else
                {
                    throw;
                }
            }

            return StatusCode(HttpStatusCode.NoContent);
        }
        [Authorize]
        [Route("GetAllFarmsByDistance")]
        public List<FarmItem> GetAllFarmsByDistance(int Radius,decimal along, decimal lat)
        {
            var userIdentity = System.Web.HttpContext.Current.User.Identity;
            string loggedInUser = userIdentity.GetUserId().ToString();
            ApplicationUser user = db.Users.Find(loggedInUser);

            return HelperClass.GetFarmsByDistance(db, user.Lat, user.Long, Radius);
        }
        // POST: api/Farms
        [ResponseType(typeof(Farm))]
        public async Task<IHttpActionResult> PostFarm(Farm farm)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            if (FarmExists(farm.Name))
            {
                return BadRequest();
            }
            else
            {
                farm.Location = HelperClass.CreatePoint(farm.Lat, farm.Long);

                var userIdentity = System.Web.HttpContext.Current.User.Identity;
                string loggedInUser = userIdentity.GetUserId().ToString();
                farm.UserNameId = loggedInUser;

                db.Farms.Add(farm);
                await db.SaveChangesAsync();
                return Ok();
            }
        }

        // DELETE: api/Farms/1
        //**** To be Setup only for Admin webiste**//
        [ResponseType(typeof(Farm))]
        public async Task<IHttpActionResult> DeleteFarm(int id)
        {
            //Farm farm = await db.Farms.FindAsync(id);
            //if (farm == null)
            //{
            //    return NotFound();
            //}

            //db.Farms.Remove(farm);
            //await db.SaveChangesAsync();

            return Ok(); 
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool FarmExists(string Name)
        {
            return db.Farms.Count(e => e.Name == Name) > 0;
        }
    }
}