namespace DateFantasy.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class InitialModel : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.Demographics",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        AddressLine = c.String(),
                        CityTown = c.String(),
                        StateProvince = c.String(),
                        PostalCode = c.String(),
                        Country = c.String(),
                        Birthdate = c.DateTime(nullable: false),
                        Orientation = c.String(),
                        Gender = c.String(),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.Favorites",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        MemberId = c.Int(nullable: false),
                        DateFavorited = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.Id)
                .ForeignKey("dbo.Members", t => t.MemberId, cascadeDelete: true)
                .Index(t => t.MemberId);
            
            CreateTable(
                "dbo.Interests",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        InterestType_Id = c.Int(),
                        Profile_Id = c.Int(),
                    })
                .PrimaryKey(t => t.Id)
                .ForeignKey("dbo.InterestTypes", t => t.InterestType_Id)
                .ForeignKey("dbo.Profiles", t => t.Profile_Id)
                .Index(t => t.InterestType_Id)
                .Index(t => t.Profile_Id);
            
            CreateTable(
                "dbo.InterestTypes",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Name = c.String(),
                        Description = c.String(),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.Members",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        UserName = c.String(),
                        MemberName = c.String(),
                        LastLogin = c.DateTime(nullable: false),
                        Created = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.Messages",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Body = c.String(),
                        MessageSent = c.DateTime(nullable: false),
                        Read = c.Boolean(nullable: false),
                        RecipientId = c.Int(nullable: false),
                        ParentId = c.Int(nullable: false),
                        Member_Id = c.Int(),
                    })
                .PrimaryKey(t => t.Id)
                .ForeignKey("dbo.Members", t => t.Member_Id)
                .Index(t => t.Member_Id);
            
            CreateTable(
                "dbo.Profiles",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        LookingFor = c.String(),
                        Introduction = c.String(),
                        Pitch = c.String(),
                        Demographics_Id = c.Int(),
                        MemberId = c.Int(nullable: false),
                    })
                .PrimaryKey(t => t.Id)
                .ForeignKey("dbo.Demographics", t => t.Demographics_Id)
                .ForeignKey("dbo.Members", t => t.MemberId)
                .Index(t => t.Demographics_Id)
                .Index(t => t.MemberId);
            
            CreateTable(
                "dbo.Photos",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Url = c.String(),
                        Description = c.String(),
                        DateAdded = c.DateTime(nullable: false),
                        IsMain = c.Boolean(nullable: false),
                        Profile_Id = c.Int(),
                    })
                .PrimaryKey(t => t.Id)
                .ForeignKey("dbo.Profiles", t => t.Profile_Id)
                .Index(t => t.Profile_Id);
            
        }
        
        public override void Down()
        {
            DropForeignKey("dbo.Profiles", "MemberId", "dbo.Members");
            DropForeignKey("dbo.Photos", "Profile_Id", "dbo.Profiles");
            DropForeignKey("dbo.Interests", "Profile_Id", "dbo.Profiles");
            DropForeignKey("dbo.Profiles", "Demographics_Id", "dbo.Demographics");
            DropForeignKey("dbo.Messages", "Member_Id", "dbo.Members");
            DropForeignKey("dbo.Favorites", "MemberId", "dbo.Members");
            DropForeignKey("dbo.Interests", "InterestType_Id", "dbo.InterestTypes");
            DropIndex("dbo.Photos", new[] { "Profile_Id" });
            DropIndex("dbo.Profiles", new[] { "MemberId" });
            DropIndex("dbo.Profiles", new[] { "Demographics_Id" });
            DropIndex("dbo.Messages", new[] { "Member_Id" });
            DropIndex("dbo.Interests", new[] { "Profile_Id" });
            DropIndex("dbo.Interests", new[] { "InterestType_Id" });
            DropIndex("dbo.Favorites", new[] { "MemberId" });
            DropTable("dbo.Photos");
            DropTable("dbo.Profiles");
            DropTable("dbo.Messages");
            DropTable("dbo.Members");
            DropTable("dbo.InterestTypes");
            DropTable("dbo.Interests");
            DropTable("dbo.Favorites");
            DropTable("dbo.Demographics");
        }
    }
}
