using DateFantasy.Extentions;
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

        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            //return base.IsValid(value, validationContext);
            if (!(value is DateTime))
            {
                throw new ValidationException("AgeRange is only valid for DateTime properties");
            }

            var birthdate = (DateTime)value;

            if(birthdate.CalculateAge() < _lowAge || birthdate.CalculateAge() > _highAge)
            {
                return new ValidationResult(this.FormatErrorMessage(validationContext.MemberName));
            }
            else
            {
                return ValidationResult.Success;
            }
        }

        public override string FormatErrorMessage(string name)
        {
            //return base.FormatErrorMessage(name);
            return string.Format(this.ErrorMessageString, name, _lowAge, _highAge);
        }
    }
}