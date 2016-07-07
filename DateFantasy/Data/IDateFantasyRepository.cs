using DateFantasy.Entities;
using DateFantasy.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace DateFantasy.Data
{
    public interface IDateFantasyRepository
    {
        Profile GetProfileByUserName(string username);
        Profile GetProfile(string memberName);
        List<RandomProfileViewModel> GetRandomProfiles(int numberToReturn);
        EditProfileViewModel GetProfileForEdit(string userName);
        EditProfileViewModel GetProfileWithPhotosForEdit(string userName);
        List<InterestType> GetInterestTypes();

        bool SaveAll();
    }
}