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
            bool ValidUser = false;
            // Den boolska variablens värde sätts till resultatet av en annan metod, CheckAdmin, och vi skickar med användarnamn och lösenord
            ValidUser = CheckAdmin(Username, Password);

            var LoggUser = new Admin // Dettta är loggning av objektet Admin. 
            {
                Username = Username,

                Password = Password,


            };
            var jsonPerson = JsonConvert.SerializeObject(LoggUser);
            Log.Information(jsonPerson);


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
        
            // Boolsk variabel för att kolla om användaren är verifierad
            bool ValidUser = false;
// ValidUser får värdet av checkUser-metoden och här skickar vi med E-mail och lösenord
            ValidUser = CheckUser(Email, Password);

            var LoggUser = new Users // Dettta är loggning av objektet NewUser. 
            {
                Email = Email,
               
                Password = Password,


            };
            var jsonPerson = JsonConvert.SerializeObject(LoggUser);
            Log.Information(jsonPerson);

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
         * Dagens datum
         * Datumet till vilket användaren är blockad */
        public bool BlockUser(int Id, int AdminId, string reason, DateTime dateTo) 
        {

    // Hitta rätt användare i databasen
            var user = db.Users.Where(x => x.ID == Id).FirstOrDefault();
            // Nytt objekt för den blockade användaren
            BlockedUsers blocked = new BlockedUsers();
 
    // Konvertera värdet av variablen DateTo så att den endast visar datum
    var toDate = dateTo.Date;

    // Variabel för dagens datum och tid
    var dateandtime = DateTime.Now;
    // Konvertera dagens datum och tid till endast datum
    var date = dateandtime.Date;

    // Om användare inte redan är blockad
    if (user.StatusID != 3)
            {
            // Användaren tilldelas status-id 3, vilket innebär blockad
    user.StatusID = 3;
    // Det nya objektet, som sparas i databasen, ´tilldelas värdena av användaruppgifterna

                blocked.UserID = Id;    
                
                blocked.SuspendedBy = AdminId;
                blocked.Reason = reason;
                blocked.DateFrom = date;
                blocked.DateTo = toDate;
                // Objektet läggs till i databasen
                db.BlockedUsers.Add(blocked);
                db.SaveChanges();

                return true;
            }
            // Om användaren redan är blockad
    else
            {
                return false;
            }
        }

    // Metod för att lägga till moderatorsbehörigheter, tar Id:t på den specifika användaren som inparameter
    public bool AssignModeratorRole(int ID) 
        {
// Hitta användaren i databasen
            var user = db.Users.Where(x => x.ID == ID).FirstOrDefault();
            // Om användaren har rollen som vanlig användare, gå vidare och ändra till moderator
    if (user.RoleID == 3)
            {
            // Användaren får roll-id 2, vilket innebär moderator
    user.RoleID = 2;

                db.SaveChanges();
                return true;
            }
// Om användaren redan har roll-id 2 (roll-id 1 har endast admin)            
            else
            {
                return false;
            }
        }
// Metod för att ta bort moderatorsbehörigheter, tar Id:t på den specifika användaren som inparameter
        public bool AssignUserRole(int ID)
        {
        // Hitta användaren i databasen
            var user = db.Users.Where(x => x.ID == ID).FirstOrDefault();
// Om användaren har moderatorsbehörigheter            
            if (user.RoleID == 2)
            {
            // Tilldela användarenroll-Id 3, vilket innebär vanlig användare
    user.RoleID = 3;
    // Spara i databasen

                db.SaveChanges();
                return true;

            }
            // Om en användare redan är vanlig
    else
            {
                return false;
            }
        }
        /*
         I vyerna för flaggade och blockade användare vill vi bland annat kunna visa upp namnet på den som flaggat eller blockat en användare.
         Vi har visserligen ID:t på dessa personer som foreign key i blocked respektive flaggeduser-tabellerna, men vi kan inte använda oss av detta Id för att visa upp ett namn när vi kommunicerar med en klient (hade vi varit i ett lokalt projekt hade det funkat).
         Vi behöver alltså skicka med ett helt objekt till klienten och därför skapar vi här ett "fejk-objekt", vilket funkar som mellanhand mellan service och klient.
         Vi skickar således detta fejk-objekt till klienten, vilket innehåller alla uppgifter.
         Vi skickar alltså separata objekt för blockade och flaggade användare samt för den användare som flaggat respektive blockat.
         */
        IEnumerable<Interface.InterfaceFlaggedUser> ILoginService.GetFlaggedUsers() // ID 2 is a FLAGGED user.
        {
          

            List<Interface.InterfaceFlaggedUser> returnList = new List<Interface.InterfaceFlaggedUser>();
            
// Loopa igenom uppgifterna om flaggade användare
            foreach (var dbUser in db.FlaggedUsers)
            {
                Interface.InterfaceUser returUser = new Interface.InterfaceUser();
                Interface.InterfaceUser Flagger = new Interface.InterfaceUser();


                InterfaceFlaggedUser interfaceflaggeduser = new InterfaceFlaggedUser();
// Det nya objektet får sina värden
                interfaceflaggeduser.ID = dbUser.ID;
                interfaceflaggeduser.Reason = dbUser.Reason;
                interfaceflaggeduser.FlaggedByUserId = dbUser.FlaggedBy;
                interfaceflaggeduser.WhoIsFlaggedID = dbUser.UserID;
                // Objekt för vem som är flaggad
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
// WhoIsFlagged tilldelas värdena av returuser och vi kan sedan använda attributet WhoIsFlagged för att kommunicera med klienten
                interfaceflaggeduser.WhoIsFlagged = returUser;

                Users FlaggedBy = (from x in db.Users
                                   where x.ID == interfaceflaggeduser.FlaggedByUserId
                                   select x).FirstOrDefault();
// Objektet flagger får sina värden
                Flagger.Email = FlaggedBy.Email;
                Flagger.Firstname = FlaggedBy.Firstname;
                Flagger.Surname = FlaggedBy.Surname;
                Flagger.Username = FlaggedBy.Username;

// Attributet Flaggedby får värdet av objektet Flagger, vi använder oss sedan av FlaggedBy-attributet i kommunikationen med klienten
                interfaceflaggeduser.FlaggedBy = Flagger;
// Hela FlaggedUser-objektet, inklusive FlaggedBy med de nya värdena, läggs till i listan som sedan returneras
                returnList.Add(interfaceflaggeduser);

           
            }
                    return returnList;
        }
// Objekt för blockade användare, beter sig på samma sätt som ovan
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

        /*
         Denna metod kollar om en blockering skall låsas upp, utifrån dagens datum samt det datum vid vilket användaren blockades.
         Metoden tar Id:t från den specifika användaren som inparameter.
         */
        private bool CheckBlockDate(int BlockedId)
        {
// Hitta användaren i BlockedUser-tabellen
            BlockedUsers BlockedUser = (from x in db.BlockedUsers
                                        where x.UserID == BlockedId
                               select x).FirstOrDefault();
// Om en användare hittas
            if (BlockedUser != null)
            {
// Om dagens datum är längre fram i tiden än det datum som blockeringen skall tas bort
                if (DateTime.Now > BlockedUser.DateTo)
                {
/*
 Användaren finns nu både i User-tabellen coh i BlockedUser-tabellen.
 I User-tabellen vill vi kunna ändra status-Id på användaren från 3 (blockad) till 1 (aktiv).
 Därför plockar vi nu även ut användaren från User-tabellen.
 */
                    var user = db.Users.Where(x => x.ID == BlockedId).FirstOrDefault();
// Här ändras Status-Id:t
                    user.StatusID = 1;
// Den blockade användaren tas bort ur BlockedUser-tabellen och finns nu således bara kvar i User-tabellen
                    db.BlockedUsers.Remove(BlockedUser);
// Ändringarna sparas i databasen
                    db.SaveChanges();
                    return true;
                }
// Om dagens datum inte är längre fram i tiden än det datum till vilket användaren ska vara blockad
                else
                {
                    return false;
                }
            }
// Om en användare inte hittas i BlockedUser-tabellen
            else
            {
                return false;
            }
        }
        /*
         Här är metoden för att visa alla moderatorer.
         I denna lista vill vi kunna se moderatorns status (aktiv eller blockad).
Vi har angett dessa statusar med ett Id i form av en siffra, men i listan vill vi ju i stället kunna visa upp ett status-namn, alltså i text-form.
Dessa namn finns i en separat Status-tabell, för vilken vi har en foreign key från Users-tabellen.
När vi ska kommunicera mellan service och klient kan vi emellertid inte använda oss av denna nyckel, varför vi skapar ett separat "fejk-objekt", vilket funkar som mellanhand mellan service och klient.
Detta objekt tilldelas värdena från så väl Users som Status-tabellen och detta samlade objekt kan vi sedan använda för att visa upp allt vi vill i klienten.
*/
        IEnumerable<Interface.InterfaceUser> ILoginService.GetModerators()
        {
            List<Interface.InterfaceUser> returnList = new List<Interface.InterfaceUser>();
// Loopa igenom uppgifterna i Users-tabellen
            foreach (var dbUser in db.Users)
            {

// Om användarna är moderatorer
                if (dbUser.RoleID == 2)
                {
// Nytt User-objekt som tilldelas värden från Users-tabellen                    
                    Interface.InterfaceUser returUser = new Interface.InterfaceUser();
                    returUser.ID = dbUser.ID;
                    returUser.StatusID = dbUser.StatusID;
                    returUser.Email = dbUser.Email;
                    returUser.RoleID = dbUser.RoleID;
                    returUser.Username = dbUser.Username;
// Hitta rätt användare i Status-tabellen, där även namnet på statusen finns
                    Status status = (from x in db.Status
                                     where x.ID == returUser.StatusID
                                     select x).FirstOrDefault();
// Nytt Status-objekt med uppgifter från Status-tabellen
                    InterfaceStatus interfacestatus = new InterfaceStatus();

                    interfacestatus.ID = status.ID;
                    interfacestatus.StatusName = status.StatusName;
/*
 Här tilldelas attributet Status i returuser-objektet värdet av det nya InterfaceStatus-objektet.
Således finns så väl användaruppgifter som statusnamn nu i returuser-bojektet, vilket är det objekt vi sedan använder oss av i kommunikation med klienten.
*/
                    returUser.Status = interfacestatus;

// Lägg till objektet i listan och returnera denna
                    returnList.Add(returUser);

                }

            }
            return returnList;
        }
// Metod för att visa alla aktiva användare, beter sig på samma sätt som metoden ovan
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
// Metod för att hitta ett User-Id via användarens E-mail, tar således mailadressen som inparameter        
        public int GetUserId(string Email)
        {
// Välj användaren i databasen utifrån dennes mailadress, ToUpper innebär att adressen kan skrivas med så väl små som stora bokstäver
            Users User = (from x in db.Users
                          where x.Email.ToUpper() == Email.ToUpper()
                          select x).FirstOrDefault();
// Id-variabel deklareras och tilldelas värdet av användarens Id från User-tabellen
            int id = User.ID;

// Id:t returneras
            return id;
        }



        // Metod för att ta bort en användares flaggning, tar den specifika anvädnarens Id som inparameter
        public bool UnflagUser(int UserId )
        {
            // Hitta rätt användare i FlaggedUser-tabellen
            FlaggedUsers removeflaggeduser = (from x in db.FlaggedUsers
                                                  where x.ID== UserId
                                                  select x).FirstOrDefault();

// För att även kunna ändra Status-Id på användaren, vilket endast finns i Users-tabellen, plockar vi här även ut användaren från Users-tabellen

            var user = db.Users.Where(x => x.ID == removeflaggeduser.UserID).FirstOrDefault();
            // Om användaren är flaggad
            if (user.StatusID == 2)
            {
// Tilldela användaren Status-Id 1, vilket innebär aktiv
                user.StatusID = 1;
                // Ta bort anvädnaren från FlaggedUser-tabellen och spara ändringarna i databasen
                db.FlaggedUsers.Remove(removeflaggeduser);

                db.SaveChanges();
                return true;
            }
// Om anvädnaren inte är flaggad
            else
            {
                return false;
            }
        }
// Metod för att kolla om en användarens mailadress redan finns i databasen, tar således mailadressen som inparameter
        public bool EmailExist(string Email)
        {
// Plockar ur den anvädnare ur databasen där mailadressen är samma som den som skickades in till metoden
            Users checkEmail = (from x in db.Users
                                where x.Email.ToUpper() == Email.ToUpper()
                                select x).FirstOrDefault();

// Om en mailadress hittas
            if (checkEmail != null)
            {
                return true;
            }
// Om en mailadress inte hittas
            else
            {
                return false;
            }
        }
// Metod för att kolla om ett visst användarnamn redan finns i databasen, tar således användarnamnet som inparameter
        public bool UsernameExist(string Username)
        {
// Plockar ut en användare ur databasen utifrån det inskickade användarnamnet
            Users checkUsername = (from x in db.Users
                                where x.Username == Username
                                select x).FirstOrDefault();
// Om ett användarnamn hittas
            if (checkUsername != null)
            {
                return true;
            }
            // Om ett användarnamn inte hittas
            else
            {
                return false;
            }
        }
// Metod för att kolla om ett visst användar-Id finns i databasen, tar såleds Id:t som inparameter
        public bool UserIdExist(int ID)
        {
// Plocka ut en anvädnare ur databasen utifrån det inskickade Id:t
            Users checkUserId = (from x in db.Users
                                where x.ID == ID
                                select x).FirstOrDefault();

// Om ett Id hittas
            if (checkUserId != null)
            {
                return true;
            }
// Om ett Id inte hittas
            else
            {
                return false;
            }
        }
// Metod för att visa uppgifterna om alla admins
        public IEnumerable<InterfaceAdmin> GetAdmins()
        {
// Lista som ska innehålla objekt för de olika administratörerna            
        List<Interface.InterfaceAdmin> returnList = new List<Interface.InterfaceAdmin>();

// Loopa igenom alla admins i databasen
            foreach (var dbAmin in db.Admin)
            {



                // Admin-objekt
                // Admin-objektet tilldelas värden afrån en admin i databasen                
                Interface.InterfaceAdmin returAdmin = new Interface.InterfaceAdmin();
                 returAdmin.ID = dbAmin.ID;
                 returAdmin.Username = dbAmin.Username;
                 returAdmin.Email = dbAmin.Email;


/*
 Admin-objektet läggs till i listan av objekt som deklarerades ovan.
 Eftersom detta sker i en loop läggs alltså ett separat objekt för varje admin till i listan (om det finns fler än en förstås).
 */
                    returnList.Add(returAdmin);

            }
// Listan av admin-objekt returneras
            return returnList;
        }

// Metod för att plocka ut en specifik admin utifrån ett användarnamn, tar således användarnamn som inparameter
        public InterfaceAdmin GetAdminByUsername(string Username)
        {
// Plocka ut en admin ur databasen utifrån det inskickade användarnamnet
            Admin CheckAdminUsername = (from x in db.Admin
                                 where x.Username == Username
                                 select x).FirstOrDefault();
// Nytt objekt innehållandes uppgifter från den specifika administratören
            InterfaceAdmin interfaceadmin = new InterfaceAdmin();

            interfaceadmin.ID = CheckAdminUsername.ID;
            interfaceadmin.Email = CheckAdminUsername.Email;
            interfaceadmin.Username = CheckAdminUsername.Username;
// Admin-objektet med alla uppgifter returneras
            return interfaceadmin;
        }
// Metod för att hitta en specifik admin utifrån ett Id, tar således Id:t som inparameter
        public InterfaceAdmin GetAdminById(int Id)
        {
// Plocka ut en admin ur databasen utifrån det inskickade Id:t
            Admin CheckAdminId = (from x in db.Admin
                                        where x.ID == Id
                                        select x).FirstOrDefault();
// Nytt Admin-objekt innehållandes uppgifter från den specifika administratören
            InterfaceAdmin interfaceadmin = new InterfaceAdmin();

            interfaceadmin.ID = CheckAdminId.ID;
            interfaceadmin.Email = CheckAdminId.Email;
            interfaceadmin.Username = CheckAdminId.Username;
// Admin-objektet returneras
            return interfaceadmin;
        }
// Metod för att kolla om en användare är moderator, tar E-mail och lösenord som inparameter
        public bool CheckModerator(string Email, string Password)
        {
            // Plocka ut användaren med den specifika mailadressen ur databasen, ToUpper innebär att adressen kan skrivas med både små coh stora bokstäver
            Users User = (from x in db.Users
                          where x.Email.ToUpper() == Email.ToUpper()
                          select x).FirstOrDefault();
// Om en användare hittas
            if (User != null)
            {
                // En variabel deklareras som används som true eller false, där 0 är false och 1 är true
                int ok = 0;


// Om en användare inte är blockad
                if (User.StatusID != 3)
                {
                    // Dekryptering av lösenordet
                    string storedPassword = User.Password;
                    byte[] passwordToBytes = Convert.FromBase64String(storedPassword);
                    byte[] saltFromDatabasePassword = new byte[16];

                    Array.Copy(passwordToBytes, 0, saltFromDatabasePassword, 0, 16);

                    var input = new Rfc2898DeriveBytes(Password, saltFromDatabasePassword, 1000);

                    byte[] hash = input.GetBytes(20);

                    ok = 1;

                    for (int i = 0; i < 20; i++)
                    {
                        // Om det finns någon skillnad mellan de två arrayerna med lösenord respektive salt och den slutliga arrayen med både lösenord och salt
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

                // Om användaren är flaggad
                else if (User.StatusID == 2)
                {
                   // Här kollas dagens datum i förhållande till det datum användaren ska vara blockad till, värdet av den boolska variabeln sätts alltså till värdet av metoden för datumkollen
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
                // Om Status-Id är något annat än 2 eller 3
                else
                {
                    return false;
                }
            }


// Om en användare inte hittas
            else
            {
                return false;
            }
        }

        // Metod för att logga in moderatorer, tar mailadress och lösenord som inparameter
        public bool ModeratorLogin(string Email, string Password)
        {
            

            // Variabel för verifierad användare
                bool ValidUser = false;
            // ValidUser tilldelas värdet av resultatet från metoden ovan, vilken kollar om användaren är moderator
            ValidUser = CheckModerator(Email, Password);

            var LoggUser = new Users // Dettta är loggning. 
            {
                Email = Email,

                Password = Password,


            };
            var jsonPerson = JsonConvert.SerializeObject(LoggUser);
            Log.Information(jsonPerson);



            // Om ValidUser blir True, returnerar även denna metod True
            if (ValidUser == true)
                {
                    return true;
                }
                else
                {
                    return false;
                }


            
        }
// Denna metod kollar om webservicen fungerar
        public bool IsAlive()
        {
            return true;
        }
// Metod för att uppdatera kontoinformation, tar emot ett objekt av en användare
        public bool UpdateAccountInfo(ReturnUser UpdatedAccountInfo)
        {
            // Hitta rätt användare i databasen
            var user = db.Users.Where(x => x.ID == UpdatedAccountInfo.ID).FirstOrDefault();

            // Kolla om användarnamnet redan finns i databasen, man ska inte kunna byta till ett användarnamn som redan finns
            Users userUsername = (from x in db.Users
                                  where x.Username == UpdatedAccountInfo.Username
                                  select x).FirstOrDefault();
// Om en användare hittas
            if (user != null)
            {
                // Om användarnamnet inte är upptaget
                if (userUsername == null)
                {
// Användarobjektet får värdena av det objekt vi skickade in i metoden, alltså den uppdaterade kontoinformationen
                 user.Email = UpdatedAccountInfo.Email;
                 user.Username = UpdatedAccountInfo.Username;
                 user.Firstname = UpdatedAccountInfo.Firstname;
                 user.Surname = UpdatedAccountInfo.Surname;

                    db.SaveChanges();
                    return true;
                }
                // Om användarnamnet är upptaget
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
    


