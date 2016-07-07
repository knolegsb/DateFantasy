using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace DateFantasy.Entities
{
    public class Member
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public string MemberName { get; set; }
        public DateTime LastLogin { get; set; }
        public DateTime Created { get; set; }
        public Profile Profile { get; set; }
        public ICollection<Message> Messages { get; set; }
        public ICollection<Favorite> Favorites { get; set; }
    }
}