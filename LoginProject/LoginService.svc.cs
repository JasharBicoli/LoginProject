using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;
using LoginProject.Interface;
using Newtonsoft.Json;
using Serilog;

namespace LoginProject
{
    // NOTE: You can use the "Rename"  xx hgh command on the "Refactor" menu to change the class name "Service1" in code, svc and config file together.
    // NOTE: In order to launch WCF Test Client for testing this service, please select Service1.svc or Service1.svc.cs at the Solution Explorer and start debugging.
    public class LoginService : Interface.ILoginService
    {
// Koppling till databasen
        AccountsEntities db = new AccountsEntities();
        
        public bool AdminLogin(string Username, string Password) //:
        {

            var LoggUser = new Admin
            {
                Username = Username,
                
                Password = Password,


            };
            var jsonPerson = JsonConvert.SerializeObject(LoggUser);
            Log.Information(jsonPerson);

            bool ValidUser = false;
            // Den boolska variablens värde sätts till resultatet av en annan metod, CheckAdmin, och vi skickar med användarnamn och lösenord
            ValidUser = CheckAdmin(Username, Password);
            // Om CheckAdmin-metoden returnerar true returnerar även denna metod true, annars false
            if (ValidUser == true)
            {
                

                return true;
                
            }
            else
            {
                return false;
            }
        }
        // Metoden för att kolla Admins användaruppgifter, som den föregående metoden hänvisar till
        private bool CheckAdmin(string Username, string Password)
        {
            // Kolla om det användarnamn som matats in finns i databasen, ToUpper innebär att användarnamnet kan skrivas med små eller stora bokstäver
            Admin Admin = (from x in db.Admin
                           where x.Username.ToUpper() == Username.ToUpper()

                           select x).FirstOrDefault();
            // Om en matching hittas i databasen
            if (Admin != null)
            {

                // Kolla om lösenordet överensstämmer med det specifika kontot
                if (Admin.Password == Password)
                {
                    return true;
                }
                else
                {
                    return false;
                }

            }
            // Om användarnamnet inte kan hittas
            else
            {
                return false;
            }
        }

// Metod för att skapa ny användare, tar ett användarobjekt som inparameter och returnerar ett nytt objekt med användarens uppgifter
        public ReturnUser CreateUser(NewUser NewUser) 
        {
// Kolla i databasen om E-mail och användarnamn redan finns, om inte, gå vidare och skapa användaren
            Users EmailCheck = (from x in db.Users
                          where x.Email.ToUpper() == NewUser.Email.ToUpper()
                          select x).FirstOrDefault();

            Users UsernameCheck = (from x in db.Users
                          where x.Username.ToUpper() == NewUser.Username.ToUpper()
                          select x).FirstOrDefault();

                var LoggUser = new Users // Dettta är loggning av objektet NewUser. 
                {
                    Email = NewUser.Email,
                    Username = NewUser.Username,
                    Firstname = NewUser.Firstname,
                    Surname = NewUser.Surname,
                    Password = NewUser.Password,

                    
                };
                var jsonPerson = JsonConvert.SerializeObject(LoggUser);
                Log.Information(jsonPerson);
            
// Om inget E-mail eller användarnamn kan hittas
            if (EmailCheck == null & UsernameCheck == null)
            {
// Hashing av lösenord med tillhörande salt
                byte[] salt;

                new RNGCryptoServiceProvider().GetBytes(salt = new byte[16]);

                var pass = new Rfc2898DeriveBytes(NewUser.Password, salt, 1000);

                byte[] passwordHash = pass.GetBytes(20);

                byte[] total = new byte[36];

                Array.Copy(salt, 0, total, 0, 16);
                Array.Copy(passwordHash, 0, total, 16, 20);
                string savedPassword = Convert.ToBase64String(total);
                /*
                 Här skapas ett nytt användarobjekt som används av resterande servicar.
                 Eftersom endast vår service skall hantera lösenord behöver vill vi inte skicka med lösenord till andra, varför detta objekt skapas.
                 */
                ReturnUser returUser = new ReturnUser();
                // Det nya objektet tilldelas värdena från användarens inmatade uppgifter
                returUser.Email = NewUser.Email;
                returUser.Username = NewUser.Username;
                returUser.Firstname = NewUser.Firstname;
                returUser.Surname = NewUser.Surname;
                // Nytt objekt som sparas i databasen, innehållande samtliga användaruppgifter
                Users CompleteUser = new Users();

                CompleteUser.Email = NewUser.Email;
                CompleteUser.Firstname = NewUser.Firstname;
                CompleteUser.Surname = NewUser.Surname;
                CompleteUser.Username = NewUser.Username;
                // Lösenordet får värdet av det tidigare hashade lösenordet, eftersom det är detta som skall sparas i databasen
                CompleteUser.Password = savedPassword;
                // Status-Id blir automatiskt 1, som innebär aktiv
                CompleteUser.StatusID = 1;
                // Role-Id 3 innebär vanlig användare
                CompleteUser.RoleID = 3;
                // Det nya användarobjektet läggs till i databasen
                db.Users.Add(CompleteUser);
                db.SaveChanges();
                // Säkerställ att det användar-id vi har överensstämmer med andra servicars Id, vilket minimerar risken för att olika användare visas upp
                returUser.ID = CompleteUser.ID;
                return returUser;
            }
            // Om E-mail och användarnamn redan finns i databasen
            else
            {
                return null;
            }
        }



        public bool CheckUser(string Email, string Password)
        {
// Kolla om användaruppgifterna finns i databasen
            Users User = (from x in db.Users
                          where x.Email.ToUpper() == Email.ToUpper()
                          select x).FirstOrDefault();
// Om användare finns
            if (User != null)
            {
            int ok = 0;

               
                // Om användaren inte är blockad
                if (User.StatusID!=3) {
                    // Lösenordet dekrypteras
                    string storedPassword = User.Password;
                    byte[] passwordToBytes = Convert.FromBase64String(storedPassword);
                    byte[] saltFromDatabasePassword = new byte[16];

                    Array.Copy(passwordToBytes, 0, saltFromDatabasePassword, 0, 16);

                    var input = new Rfc2898DeriveBytes(Password, saltFromDatabasePassword, 1000);

                    byte[] hash = input.GetBytes(20);

                    ok = 1;

                    for (int i = 0; i < 20; i++)
                    {
// Om något skiljer sig i de olika arrayerna med salt och lösenord, blir ok-variabeln 0 vilket motsvarar false
                        if (passwordToBytes[i + 16] != hash[i])
                        {
                            ok = 0;
                        }
                    }

                    if (ok == 1)
                    {
                        return true;
                    }

                   
                    else
                    {
                        return false;
                    }
                    
                }
                // Om användaren är blockad
                else if (User.StatusID == 3)
                {
                    bool CheckedBlockedStatus;
/*
 Den boolska variabeln tilldelas värdet av en annan metod som kollar dagens datum samt det datum som användaren blockades.
 Id:t som skickas med ser till att rätt användare kollas.
 */
                    CheckedBlockedStatus =  CheckBlockDate(User.ID);
                    if (CheckedBlockedStatus == true)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }



            else
            {
                return false;
            }
        }
        // Metod för att logga in
        public bool UserLogin(string Email, string Password)
        {

            var LoggUser = new Users
            {
                Email = Email,
                
                Password = Password,


            };
            var jsonPerson = JsonConvert.SerializeObject(LoggUser);
            Log.Information(jsonPerson);

            // Boolsk variabel för att kolla om användaren är verifierad
            bool ValidUser = false;
// ValidUser får värdet av checkUser-metoden och här skickar vi med E-mail och lösenord
            ValidUser = CheckUser(Email, Password);

            if (ValidUser == true)
            {
                return true;
            }
            else
            {
                return false;
            }
            
            
        }
               // Metod för att radera användare
        public bool DeleteUser(int UserId)
        {
            // Hitta rätt användare i databasen
            Users FoundUser = (from x in db.Users
                               where x.ID == UserId
                               select x).FirstOrDefault();
            // Om en användare hittas
            if (FoundUser != null)
            {
                // Ta bort användaren och spara ändringarna i databasen
                db.Users.Remove(FoundUser);
                db.SaveChanges();
                return true;

            }
// Om användaren inte finns
            else
            {
                return false;
            }
        }

/*
 Metod för att flagga en användare.
 Här skickar vi med ID:t av den som flaggat, den användare som ska flaggas samt orsaken till varför användaren ska flaggas.
 */
        public bool FlagUser(int FlaggedByUserId, string Reason, int FlaggedUserId) 
        {


// Välj användaren från databasen           
            var user = db.Users.Where(x => x.ID == FlaggedUserId).FirstOrDefault();
            // Om användaren inte redan är flaggad
            if (user.StatusID!=2)
            {
                FlaggedUsers flaggedUser = new FlaggedUsers();
                // Användaren tilldelas status-Id 2, vilket innebär att användaren blir flaggad
                user.StatusID = 2;
// Det nya objektet tilldelas Id-värdet av den användare som har gjort flaggningen
                flaggedUser.FlaggedBy = FlaggedByUserId;
// Objektet får värdet av orsaks-strängen vi skickade in i denna metod
                flaggedUser.Reason = Reason;
// ID:t på den flaggade användaren
                flaggedUser.UserID = FlaggedUserId;

// Det nya objektet sparas i databasen
                db.FlaggedUsers.Add(flaggedUser);

                db.SaveChanges();
                return true;
            }
            // Om användaren redan är flaggad
            else
            {
                return false;
            }
        }
        /*
         Metod för att blocka en användare.
         Inparametrarna är:
         * ID:t på den användare som ska blockas
         * ID:t på den admin som blockar användaren
         * Orsaken till blockningen
         * 
         * */
        public bool BlockUser(int Id, int AdminId, string reason, DateTime dateTo) 
        {


            var user = db.Users.Where(x => x.ID == Id).FirstOrDefault();

            BlockedUsers blocked = new BlockedUsers();
 
            var toDate = dateTo.Date; //convert Date and Time to date only.(date-to)

            var dateandtime = DateTime.Now; //convert Date and Time to date only. (date-from)
            var date = dateandtime.Date;

            if (user.StatusID != 3) // status id = 3 is a blocked user.
            {
                user.StatusID = 3;


                blocked.UserID = Id;    
                
                blocked.SuspendedBy = AdminId;
                blocked.Reason = reason;
                blocked.DateFrom = date;
                blocked.DateTo = toDate;

                db.BlockedUsers.Add(blocked);
                db.SaveChanges();

                return true;
            }
            else
            {
                return false;
            }
        }

        public bool AssignModeratorRole(int ID) 
        {

            var user = db.Users.Where(x => x.ID == ID).FirstOrDefault();
            if (user.RoleID == 3) // role-id=3 is user.
            {
                user.RoleID = 2;

                db.SaveChanges();
                return true;
            }
            
            else
            {
                return false;
            }
        }

        public bool AssignUserRole(int ID)
        {

            var user = db.Users.Where(x => x.ID == ID).FirstOrDefault();
            
            if (user.RoleID == 2) //role-id=2 is moderator
            {
                user.RoleID = 3;

                db.SaveChanges();
                return true;

            }
            else
            {
                return false;
            }
        }

        IEnumerable<Interface.InterfaceFlaggedUser> ILoginService.GetFlaggedUsers() // ID 2 is a FLAGGED user.
        {
          

            List<Interface.InterfaceFlaggedUser> returnList = new List<Interface.InterfaceFlaggedUser>();
            

            foreach (var dbUser in db.FlaggedUsers)
            {
                Interface.InterfaceUser returUser = new Interface.InterfaceUser();
                Interface.InterfaceUser Flagger = new Interface.InterfaceUser();


                InterfaceFlaggedUser interfaceflaggeduser = new InterfaceFlaggedUser();

                interfaceflaggeduser.ID = dbUser.ID;
                interfaceflaggeduser.Reason = dbUser.Reason;
                interfaceflaggeduser.FlaggedByUserId = dbUser.FlaggedBy;
                interfaceflaggeduser.WhoIsFlaggedID = dbUser.UserID;

                Users user = (from x in db.Users
                             where x.ID == interfaceflaggeduser.WhoIsFlaggedID
                             select x).FirstOrDefault();

                returUser.StatusID = user.StatusID;
                returUser.Email = user.Email;
                returUser.RoleID = user.RoleID;
                returUser.Username = user.Username;
                returUser.Firstname = user.Firstname;
                returUser.Surname = user.Surname;
                returUser.ID = user.ID;

                interfaceflaggeduser.WhoIsFlagged = returUser;

                Users FlaggedBy = (from x in db.Users
                                   where x.ID == interfaceflaggeduser.FlaggedByUserId
                                   select x).FirstOrDefault();

                Flagger.Email = FlaggedBy.Email;
                Flagger.Firstname = FlaggedBy.Firstname;
                Flagger.Surname = FlaggedBy.Surname;
                Flagger.Username = FlaggedBy.Username;

                interfaceflaggeduser.FlaggedBy = Flagger;

                returnList.Add(interfaceflaggeduser);

           
            }
                    return returnList;
        }

        IEnumerable<Interface.InterfaceBlockedUser> ILoginService.GetBlockedUsers()
        {
            List<Interface.InterfaceBlockedUser> returnList = new List<Interface.InterfaceBlockedUser>();


            foreach (var dbUser in db.BlockedUsers)
            {

                    Interface.InterfaceUser returUser = new Interface.InterfaceUser();
                    InterfaceBlockedUser interfaceblockeduser = new InterfaceBlockedUser();
                    InterfaceAdmin interfaceadmin = new InterfaceAdmin();

                    interfaceblockeduser.ID = dbUser.ID;
                    interfaceblockeduser.Reason = dbUser.Reason;
                    interfaceblockeduser.SuspendedBy = dbUser.SuspendedBy;
                    interfaceblockeduser.DateFrom = dbUser.DateFrom;
                    interfaceblockeduser.DateTo = dbUser.DateTo;
                    interfaceblockeduser.UserId = dbUser.UserID;

                    Users user = (from x in db.Users
                                  where x.ID == interfaceblockeduser.UserId
                                  select x).FirstOrDefault();

                returUser.ID = user.ID;
                returUser.Username = user.Username;
                returUser.Firstname = user.Firstname;
                returUser.Surname = user.Surname;
                returUser.Email = user.Email;

                Admin admin = (from x in db.Admin
                               where x.ID == interfaceblockeduser.SuspendedBy
                               select x).FirstOrDefault();

                interfaceadmin.ID = admin.ID;
                interfaceadmin.Username = admin.Username;

                interfaceblockeduser.Banner = interfaceadmin;
                interfaceblockeduser.UserObject = returUser;

                returnList.Add(interfaceblockeduser);

               

            }
            return returnList;
        }


        private bool CheckBlockDate(int BlockedId)
        {
            BlockedUsers BlockedUser = (from x in db.BlockedUsers
                                        where x.UserID == BlockedId
                               select x).FirstOrDefault();

            if (BlockedUser != null)
            {
                if (DateTime.Now > BlockedUser.DateTo)
                {
                    var user = db.Users.Where(x => x.ID == BlockedId).FirstOrDefault();
                    user.StatusID = 1;

                    db.BlockedUsers.Remove(BlockedUser);

                    db.SaveChanges();
                    return true;
                }

                else
                {
                    return false;
                }
            }

            else
            {
                return false;
            }
        }

        IEnumerable<Interface.InterfaceUser> ILoginService.GetModerators()
        {
            List<Interface.InterfaceUser> returnList = new List<Interface.InterfaceUser>();

            foreach (var dbUser in db.Users)
            {

                if (dbUser.RoleID == 2)
                {

                    Interface.InterfaceUser returUser = new Interface.InterfaceUser();
                    returUser.ID = dbUser.ID;
                    returUser.StatusID = dbUser.StatusID;
                    returUser.Email = dbUser.Email;
                    returUser.RoleID = dbUser.RoleID;
                    returUser.Username = dbUser.Username;

                    Status status = (from x in db.Status
                                     where x.ID == returUser.StatusID
                                     select x).FirstOrDefault();

                    InterfaceStatus interfacestatus = new InterfaceStatus();

                    interfacestatus.ID = status.ID;
                    interfacestatus.StatusName = status.StatusName;

                    returUser.Status = interfacestatus;


                    returnList.Add(returUser);

                }

            }
            return returnList;
        }

        IEnumerable<Interface.InterfaceUser> ILoginService.GetActiveUsers()
        {
            List<Interface.InterfaceUser> returnList = new List<Interface.InterfaceUser>();

            foreach (var dbUser in db.Users)
            {

                if ((dbUser.StatusID == 1) || (dbUser.StatusID == 2))
                {

                    InterfaceStatus interfaceStatus = new InterfaceStatus();

                    Interface.InterfaceUser returUser = new Interface.InterfaceUser();

                    InterfaceRole interfacerole = new InterfaceRole();

                    returUser.StatusID = dbUser.StatusID;
                    returUser.Email = dbUser.Email;
                    returUser.RoleID = dbUser.RoleID;
                    returUser.Username = dbUser.Username;
                    returUser.Firstname = dbUser.Firstname;
                    returUser.Surname = dbUser.Surname;
                    returUser.ID = dbUser.ID;


                    Status realStatus = (from x in db.Status
                                         where x.ID == returUser.StatusID
                                         select x).FirstOrDefault();

                    interfaceStatus.ID = realStatus.ID;
                    interfaceStatus.StatusName = realStatus.StatusName;
                    

                    returUser.Status = interfaceStatus;

                    Roles realRole = (from x in db.Roles
                                         where x.ID == returUser.RoleID
                                         select x).FirstOrDefault();

                    interfacerole.ID = realRole.ID;
                    interfacerole.Role = realRole.Role;

                    returUser.Roles = interfacerole;

                    returnList.Add(returUser);

                }

            }
            return returnList;
        }

        public int GetUserId(string Email)
        {
            Users User = (from x in db.Users
                          where x.Email.ToUpper() == Email.ToUpper()
                          select x).FirstOrDefault();

            int id = User.ID;


            return id;
        }

        

        public bool UnflagUser(int UserId )
        {

            var LoggUser = new Users
            {
                ID = UserId


            };
            var jsonPerson = JsonConvert.SerializeObject(LoggUser);
            Log.Information(jsonPerson);
            FlaggedUsers removeflaggeduser = (from x in db.FlaggedUsers
                                                  where x.ID== UserId
                                                  select x).FirstOrDefault();


            var user = db.Users.Where(x => x.ID == removeflaggeduser.UserID).FirstOrDefault();
            if (user.StatusID == 2) //status id =2 is a flagged user.
            {
                user.StatusID = 1;
                db.FlaggedUsers.Remove(removeflaggeduser);

                db.SaveChanges();
                return true;
            }
            else
            {
                return false;
            }
        }

        public bool EmailExist(string Email)
        {
            Users checkEmail = (from x in db.Users
                                where x.Email.ToUpper() == Email.ToUpper()
                                select x).FirstOrDefault();

            if (checkEmail != null)
            {
                return true;
            }

            else
            {
                return false;
            }
        }

        public bool UsernameExist(string Username)
        {
            Users checkUsername = (from x in db.Users
                                where x.Username == Username
                                select x).FirstOrDefault();

            if (checkUsername != null)
            {
                return true;
            }

            else
            {
                return false;
            }
        }

        public bool UserIdExist(int ID)
        {
            Users checkUserId = (from x in db.Users
                                where x.ID == ID
                                select x).FirstOrDefault();

            if (checkUserId != null)
            {
                return true;
            }

            else
            {
                return false;
            }
        }

        public IEnumerable<InterfaceAdmin> GetAdmins()
        {
            List<Interface.InterfaceAdmin> returnList = new List<Interface.InterfaceAdmin>();

            foreach (var dbAmin in db.Admin)
            {

               

                 Interface.InterfaceAdmin returAdmin = new Interface.InterfaceAdmin();
                 returAdmin.ID = dbAmin.ID;
                 returAdmin.Username = dbAmin.Username;
                 returAdmin.Email = dbAmin.Email;



                    returnList.Add(returAdmin);

            }
            return returnList;
        }

        public InterfaceAdmin GetAdminByUsername(string Username)
        {
            Admin CheckAdminUsername = (from x in db.Admin
                                 where x.Username == Username
                                 select x).FirstOrDefault();

            InterfaceAdmin interfaceadmin = new InterfaceAdmin();

            interfaceadmin.ID = CheckAdminUsername.ID;
            interfaceadmin.Email = CheckAdminUsername.Email;
            interfaceadmin.Username = CheckAdminUsername.Username;

            return interfaceadmin;
        }

        public InterfaceAdmin GetAdminById(int Id)
        {
            Admin CheckAdminId = (from x in db.Admin
                                        where x.ID == Id
                                        select x).FirstOrDefault();

            InterfaceAdmin interfaceadmin = new InterfaceAdmin();

            interfaceadmin.ID = CheckAdminId.ID;
            interfaceadmin.Email = CheckAdminId.Email;
            interfaceadmin.Username = CheckAdminId.Username;

            return interfaceadmin;
        }

        public bool CheckModerator(string Email, string Password)
        {
            Users User = (from x in db.Users
                          where x.Email.ToUpper() == Email.ToUpper()
                          select x).FirstOrDefault();
            if (User != null)
            {
                int ok = 0;



                if (User.StatusID != 3)
                {

                    string storedPassword = User.Password;
                    byte[] passwordToBytes = Convert.FromBase64String(storedPassword);
                    byte[] saltFromDatabasePassword = new byte[16];

                    Array.Copy(passwordToBytes, 0, saltFromDatabasePassword, 0, 16);

                    var input = new Rfc2898DeriveBytes(Password, saltFromDatabasePassword, 1000);

                    byte[] hash = input.GetBytes(20);

                    ok = 1;

                    for (int i = 0; i < 20; i++)
                    {
                        if (passwordToBytes[i + 16] != hash[i])
                        {
                            ok = 0;
                        }
                    }

                    if (ok == 1)
                    {
                        return true;
                    }


                    else
                    {
                        return false;
                    }

                }

                else if (User.StatusID == 2)
                {
                    bool CheckedBlockedStatus;
                    CheckedBlockedStatus = CheckBlockDate(User.ID);
                    if (CheckedBlockedStatus == true)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }



            else
            {
                return false;
            }
        }

        public bool ModeratorLogin(string Email, string Password)
        {

            var LoggUser = new Users
            {
                Email = Email,
                
                Password = Password,


            };
            var jsonPerson = JsonConvert.SerializeObject(LoggUser);
            Log.Information(jsonPerson);


            bool ValidUser = false;
                ValidUser = CheckModerator(Email, Password);

                if (ValidUser == true)
                {
                    return true;
                }
                else
                {
                    return false;
                }


            
        }

        public bool IsAlive()
        {
            return true;
        }

        public bool UpdateAccountInfo(ReturnUser UpdatedAccountInfo)
        {   
            var user = db.Users.Where(x => x.ID == UpdatedAccountInfo.ID).FirstOrDefault();

            Users userUsername = (from x in db.Users
                                  where x.Username == UpdatedAccountInfo.Username
                                  select x).FirstOrDefault();

            if (user != null)
            {
                if (userUsername == null)
                {

                 user.Email = UpdatedAccountInfo.Email;
                 user.Username = UpdatedAccountInfo.Username;
                 user.Firstname = UpdatedAccountInfo.Firstname;
                 user.Surname = UpdatedAccountInfo.Surname;

                    db.SaveChanges();
                    return true;
                }
                else
                {
                        
                return false;
                }
            }
            

            else
            {
                return false;
            }

        }

        public int CountActiveUsers()
        {

            int rows = db.Users.Where(x => x.StatusID != 3).Count();

            return rows;
        }

        public int CountFlaggedUsers()
        {
            int rows = db.FlaggedUsers.Count();

            return rows;
        }

        public int CountBlockedUsers()
        {
            int rows = db.BlockedUsers.Count();

            return rows;
        }
    }
    }
    


