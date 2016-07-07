using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace DateFantasy.Extentions
{
    public static class DateTimeExtension
    {
        public static int CalculateAge(this DateTime dateTime)
        {
            var age = DateTime.Today.Year - dateTime.Year;
            if (dateTime.AddYears(age) > DateTime.Today)
            {
                age--;
            }

            return age;
        }
    }
}