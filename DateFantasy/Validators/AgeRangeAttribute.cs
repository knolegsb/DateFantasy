using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace DateFantasy.Validators
{
    public class AgeRangeAttribute : ValidationAttribute
    {
        private int _lowAge;
        private int _highAge;

        public AgeRangeAttribute(int lowAge, int highAge)
        {
            _lowAge = lowAge;
            _highAge = highAge;
            ErrorMessage = "{0} must be between {1} and {2}.";
        }
    }
}