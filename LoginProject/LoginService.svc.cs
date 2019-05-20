using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;
using LoginProject.Interface;

namespace LoginProject
{
    // NOTE: You can use the "Rename"  xx hgh command on the "Refactor" menu to change the class name "Service1" in code, svc and config file together.
    // NOTE: In order to launch WCF Test Client for testing this service, please select Service1.svc or Service1.svc.cs at the Solution Explorer and start debugging.
    public class LoginService : Interface.ILoginService
    {
        AccountsEntities db = new AccountsEntities();
        public bool AdminLogin(string Username, string Password) //:
        {
            bool ValidUser = false;
            ValidUser = CheckAdmin(Username, Password);

            if (ValidUser == true)
            {
                

                return true;
                
            }
            else
            {
                return false;
            }
        }
        private bool CheckAdmin(string Username, string Password)
        {
            Admin Admin = (from x in db.Admin
                           where x.Username.ToUpper() == Username.ToUpper()

                           select x).FirstOrDefault();

            if (Admin != null)
            {


                if (Admin.Password == Password)
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


        public ReturnUser CreateUser(NewUser NewUser) 
        {
            Users EmailCheck = (from x in db.Users
                          where x.Email.ToUpper() == NewUser.Email.ToUpper()
                          select x).FirstOrDefault();

            Users UsernameCheck = (from x in db.Users
                          where x.Username.ToUpper() == NewUser.Username.ToUpper()
                          select x).FirstOrDefault();


            if (EmailCheck == null & UsernameCheck == null)
            {
                byte[] salt;

                new RNGCryptoServiceProvider().GetBytes(salt = new byte[16]);

                var pass = new Rfc2898DeriveBytes(NewUser.Password, salt, 1000);

                byte[] passwordHash = pass.GetBytes(20);

                byte[] total = new byte[36];

                Array.Copy(salt, 0, total, 0, 16);
                Array.Copy(passwordHash, 0, total, 16, 20);
                string savedPassword = Convert.ToBase64String(total);

                ReturnUser returUser = new ReturnUser();
                returUser.Email = NewUser.Email;
                returUser.Username = NewUser.Username;
                returUser.Firstname = NewUser.Firstname;
                returUser.Surname = NewUser.Surname;

                Users CompleteUser = new Users();

                CompleteUser.Email = NewUser.Email;
                CompleteUser.Firstname = NewUser.Firstname;
                CompleteUser.Surname = NewUser.Surname;
                CompleteUser.Username = NewUser.Username;

                CompleteUser.Password = savedPassword;
                CompleteUser.StatusID = 1;
                CompleteUser.RoleID = 3;
                
                db.Users.Add(CompleteUser);
                db.SaveChanges();
                returUser.ID = CompleteUser.ID;
                return returUser;
            }

            else
            {
                return null;
            }
        }



        public bool CheckUser(string Email, string Password)
        {
            Users User = (from x in db.Users
                          where x.Email.ToUpper() == Email.ToUpper()
                          select x).FirstOrDefault();
            if (User != null)
            {
            int ok = 0;

               

                if (User.StatusID!=3) {

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

                else if (User.StatusID == 3)
                {
                    bool CheckedBlockedStatus;
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
        public bool UserLogin(string Email, string Password)
        {
            bool ValidUser = false;
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
               
        public bool DeleteUser(int UserId)
        {
            Users FoundUser = (from x in db.Users
                               where x.ID == UserId
                               select x).FirstOrDefault();

            if (FoundUser != null)
            {
                db.Users.Remove(FoundUser);
                db.SaveChanges();
                return true;

            }
            else
            {
                return false;
            }
        }

        public bool FlagUser(int FlaggedByUserId, string Reason, int FlaggedUserId) 
        {


           
            var user = db.Users.Where(x => x.ID == FlaggedUserId).FirstOrDefault();
            if(user.StatusID!=2) //status id =2 is a flagged user.
            {
                FlaggedUsers flaggedUser = new FlaggedUsers();
                user.StatusID = 2;
                flaggedUser.FlaggedBy = FlaggedByUserId;
                flaggedUser.Reason = Reason;
                flaggedUser.UserID = FlaggedUserId;

                db.FlaggedUsers.Add(flaggedUser);

                db.SaveChanges();
                return true;
            }
            else
            {
                return false;
            }
        }

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
    }
    
}

