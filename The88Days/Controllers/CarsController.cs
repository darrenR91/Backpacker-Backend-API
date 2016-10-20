using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
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
    [RoutePrefix("api/Cars")]
    public class CarsController : ApiController
    {
        
        private ApplicationDbContext db = new ApplicationDbContext();

        // GET: api/Cars
        public IQueryable<Car> GetCars()
        {
            return db.Cars;
        }
        [Route("AddCar")]
        public async Task<IHttpActionResult> AddCar(Car model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var userIdentity = System.Web.HttpContext.Current.User.Identity;
            string loggedInUser = userIdentity.GetUserId().ToString();
            model.UserNameId = loggedInUser;
            
            model.CarPhoto = "https://the88daysblob.blob.core.windows.net/carphotos/" + model.UserNameId;

            if (!model.Long.Equals(0) & !model.Lat.Equals(0))
            {
                model.Location = HelperClass.CreatePoint(model.Lat, model.Long);
            }

            db.Cars.Add(model);
            await db.SaveChangesAsync();
            return Ok();
        }
        [Authorize]
        [Route("car")]
        //[ResponseType(typeof(List<CarItem>))]
        public List<CarItem> GetAllCarsByDistance([FromUri]CarSearch carSearch)
        {
            var userIdentity = System.Web.HttpContext.Current.User.Identity;
            string loggedInUser = userIdentity.GetUserId().ToString();
            ApplicationUser user = db.Users.Find(loggedInUser);

            carSearch.lat = user.Lat;
            carSearch.aLong = user.Long;

            List<CarItem> carList = HelperClass.GetCarsByDistance(db, carSearch);

            return carList;
        }
        [Authorize]
        [Route("getMyCar")]
        //[ResponseType(typeof(List<CarItem>))]
        public CarItem getMyCar()
        {
            var userIdentity = System.Web.HttpContext.Current.User.Identity;
            string loggedInUser = userIdentity.GetUserId().ToString();
           

            Car car = db.Cars.Where(loc => loc.UserNameId == loggedInUser)
                           .FirstOrDefault();
            CarItem carItem = new CarItem();
            if (car == null)
            {
                return carItem;
            }
            else {
                


                carItem.title = car.Title;
                carItem.description = car.Description;
                carItem.aLong = car.Long;
                carItem.lat = car.Lat;
                carItem.carPhoto = car.CarPhoto;
                carItem.price = car.Price;
                carItem.availableFrom = car.AvailableFrom;
                carItem.availableTo = car.AvailableTo;
                carItem.userNameId = car.UserNameId;
                carItem.contactNumber = car.ContactNumber;
            }
            return carItem;
        }
        // GET: api/Cars/5
        [ResponseType(typeof(Car))]
        public async Task<IHttpActionResult> GetCar(int id)
        {
            Car car = await db.Cars.FindAsync(id);
            if (car == null)
            {
                return NotFound();
            }

            return Ok(car);
        }

        // PUT: api/Cars/5
        [ResponseType(typeof(void))]
        public async Task<IHttpActionResult> PutCar(int id, Car car)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != car.CarId)
            {
                return BadRequest();
            }

            db.Entry(car).State = EntityState.Modified;

            try
            {
                await db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!CarExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return StatusCode(HttpStatusCode.NoContent);
        }

        // POST: api/Cars
        [ResponseType(typeof(Car))]
        public async Task<IHttpActionResult> PostCar(CarAddItem carModel)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            Car car = new Car();
            var userIdentity = System.Web.HttpContext.Current.User.Identity;
            string loggedInUser = userIdentity.GetUserId().ToString();
            car.UserNameId = loggedInUser;


            car.AvailableFrom = carModel.AvailableFrom;
            car.AvailableTo = carModel.AvailableTo;
            car.ContactNumber = carModel.ContactNumber;
            car.Description = carModel.Description;
            car.Lat = carModel.Lat;
            car.Long = carModel.Long;
            car.Price = carModel.Price;
            car.Title = carModel.Title;


            car.CarPhoto = "https://the88daysblob.blob.core.windows.net/carphotos/" + car.UserNameId;

            if (!car.Long.Equals(0) & !car.Lat.Equals(0))
            {
                car.Location = HelperClass.CreatePoint(car.Lat, car.Long);
            }
            if (carModel.CityLocation != null)
            {
                if (carModel.CityLocation == "Cairns")
                {
                    car.Location = HelperClass.CreatePointForCity(-16.920334, 145.770860);
                    car.Long = (decimal)145.770860;
                    car.Lat = (decimal)-16.920334;
                }
                else if (carModel.CityLocation == "Townsville")
                {
                    car.Location = HelperClass.CreatePointForCity(-19.257622, 146.817879);
                    car.Long = (decimal)146.817879;
                    car.Lat = (decimal)-19.257622;
                }
                else if (carModel.CityLocation == "Rockhampton")
                {
                    car.Location = HelperClass.CreatePointForCity(-23.377915, 150.510103);
                    car.Long = (decimal)150.510103;
                    car.Lat = (decimal)-23.377915;
                }
                else if (carModel.CityLocation == "Bundaberg")
                {
                    car.Location = HelperClass.CreatePointForCity(-24.864963, 152.348653);
                    car.Long = (decimal)152.348653;
                    car.Lat = (decimal)-24.864963;
                }
                else if (carModel.CityLocation == "Brisbane")
                {
                    car.Location = HelperClass.CreatePointForCity(-27.471011, 153.023449);
                    car.Long = (decimal)153.023449;
                    car.Lat = (decimal)-27.471011;
                }
                else if (carModel.CityLocation == "Sydney")
                {
                    car.Location = HelperClass.CreatePointForCity(-33.867487, 151.206990);
                    car.Long = (decimal)151.206990;
                    car.Lat = (decimal)-33.867487;
                }
                else if (carModel.CityLocation == "Canberra")
                {
                    car.Location = HelperClass.CreatePointForCity(-35.282000, 149.128684);
                    car.Long = (decimal)149.128684;
                    car.Lat = (decimal)-35.282000;
                }
                else if (carModel.CityLocation == "Melbourne")
                {
                    car.Location = HelperClass.CreatePointForCity(-37.814107, 144.963280);
                    car.Long = (decimal)144.963280;
                    car.Lat = (decimal)-37.814107;
                }
                else if (carModel.CityLocation == "Adelaide")
                {
                    car.Location = HelperClass.CreatePointForCity(-34.928621, 138.599959);
                    car.Long = (decimal)138.599959;
                    car.Lat = (decimal)-34.928621;
                }
                else if (carModel.CityLocation == "Perth")
                {
                    car.Location = HelperClass.CreatePointForCity(-31.953513, 115.857047);
                    car.Long = (decimal)115.857047;
                    car.Lat = (decimal)-31.953513;
                }
                else if (carModel.CityLocation == "Broome")
                {
                    car.Location = HelperClass.CreatePointForCity(-17.951221, 122.244327);
                    car.Long = (decimal)122.244327;
                    car.Lat = (decimal)-17.951221;
                }
                else if (carModel.CityLocation == "Darwin")
                {
                    car.Location = HelperClass.CreatePointForCity(-12.462827, 130.841777);
                    car.Long = (decimal)130.841777;
                    car.Lat = (decimal)-12.462827;
                }
            }

                db.Cars.Add(car);
            await db.SaveChangesAsync();
            return Ok();


            //if (!ModelState.IsValid)
            //{
            //    return BadRequest(ModelState);
            //}

            //db.Cars.Add(car);
            //await db.SaveChangesAsync();

            //return CreatedAtRoute("DefaultApi", new { id = car.CarId }, car);
        }

        // DELETE: api/Cars/5
        [ResponseType(typeof(Car))]
        public async Task<IHttpActionResult> DeleteCar(int id)
        {
            Car car = await db.Cars.FindAsync(id);
            if (car == null)
            {
                return NotFound();
            }

            db.Cars.Remove(car);
            await db.SaveChangesAsync();

            return Ok(car);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool CarExists(int id)
        {
            return db.Cars.Count(e => e.CarId == id) > 0;
        }
    }
}