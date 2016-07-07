using DateFantasy.Entities;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;

namespace DateFantasy.Data
{
    public class DateFantasyContext : DbContext
    {
        public DateFantasyContext() : base("DateFantasy")
        {
            Database.SetInitializer<DateFantasyContext>(new DateFantasyDbInitializer());
        }

        public DbSet<Member> Members { get; set; }
        public DbSet<InterestType> InterestTypes { get; set; }
        public DbSet<Interest> Interests { get; set; }
        public DbSet<Demographics> Demographics { get; set; }
        public DbSet<Favorite> Favorites { get; set; }
        public DbSet<Message> Messages { get; set; }
        public DbSet<Photo> Photos { get; set; }
        public DbSet<Profile> Profile { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Member>()
                .HasOptional<Profile>(m => m.Profile)
                .WithRequired(m => m.Member)
                .Map(p => p.MapKey("MemberId"));
        }
    }
}