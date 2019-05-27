using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;

namespace LoginProject.Interface
{
    // NOTE: You can use the "Rename" command on the "Refactor" menu to change the interface name "IService1" in both code and config file together.
    [ServiceContract]
    public interface ILoginService
    {

        [OperationContract]
        bool IsAlive();
        [OperationContract]
        int CountActiveUsers();

        [OperationContract]
        int CountFlaggedUsers();

        [OperationContract]
        int CountBlockedUsers();

        [OperationContract]
        ReturnUser CreateUser(NewUser NewUser);

        

        [OperationContract]
        bool UserLogin(string Email, string Password);

        [OperationContract]
        bool AdminLogin(string Username, string Password);

        [OperationContract]
        bool DeleteUser(int UserId);

        [OperationContract]
        bool UnflagUser(int UserId);

        [OperationContract]
        bool CheckUser(string Email, string Password);

        [OperationContract]
        bool CheckModerator(string Email, string Password);

        [OperationContract]
        bool ModeratorLogin(string Email, string Password);

        [OperationContract]
        int GetUserId(string Email);

        [OperationContract]
        bool UpdateAccountInfo(ReturnUser UpdatedAccountInfo);

        [OperationContract]
        IEnumerable<InterfaceFlaggedUser> GetFlaggedUsers();
        [OperationContract]
        IEnumerable<InterfaceBlockedUser> GetBlockedUsers();

        [OperationContract]
        IEnumerable<InterfaceUser> GetModerators();

        [OperationContract]
        IEnumerable<InterfaceAdmin> GetAdmins();

        [OperationContract]
        IEnumerable<InterfaceUser> GetActiveUsers();

        [OperationContract]
        bool FlagUser(int FlaggedByUserId, string Reason, int FlaggedUserId);

        [OperationContract]
        bool BlockUser(int Id, int AdminId, string reason, DateTime dateTo);

        [OperationContract]
        bool AssignModeratorRole(int ID);

        [OperationContract]
        bool AssignUserRole(int ID);


        [OperationContract]
        bool EmailExist(string Email);

        [OperationContract]
        bool UsernameExist(string Username);

        [OperationContract]
        bool UserIdExist(int ID);

        [OperationContract]
        InterfaceAdmin GetAdminByUsername(string Username);

        [OperationContract]
        InterfaceAdmin GetAdminById(int Id);
        // TODO: Add your service operations here
    }


    // Use a data contract as illustrated in the sample below to add composite types to service operations.
    [DataContract]
    public class CompositeType
    {
        bool boolValue = true;
        string stringValue = "Hello ";

        [DataMember]
        public bool BoolValue
        {
            get { return boolValue; }
            set { boolValue = value; }
        }

        [DataMember]
        public string StringValue
        {
            get { return stringValue; }
            set { stringValue = value; }
        }

    }
    [DataContract]
    public class InterfaceUser
    {
        [DataMember]
        public int ID { get; set; }

        [DataMember]
        public string Email { get; set; }

        [DataMember]
        public string Username { get; set; }

        [DataMember]
        public string Firstname { get; set; }

        [DataMember]
        public string Surname { get; set; }

        [DataMember]
        public string Password { get; set; }

        [DataMember]
        public Nullable<int> RoleID { get; set; }

        [DataMember]
        public Nullable<int> StatusID { get; set; }

        [DataMember]

        public  InterfaceRole Roles { get; set; }

        [DataMember]
        public InterfaceStatus Status { get; set; }
    }


    [DataContract]
    public class NewUser
    {


        [DataMember]
        [Required]
        public string Email { get; set; }

        [DataMember]
        [Required]
        public string Password { get; set; }

        [DataMember]
        [Required]
        public string Username { get; set; }


        [DataMember]
        [Required]
        public string Firstname { get; set; }

        [DataMember]
        [Required]
        public string Surname { get; set; }
    }


    [DataContract]
    public class ReturnUser
    {

        [DataMember]
        public int ID { get; set; }

        [DataMember]
        public string Email { get; set; }


        [DataMember]
        public string Username { get; set; }


        [DataMember]
        public string Firstname { get; set; }

        [DataMember]
        public string Surname { get; set; }
    }

    [DataContract]
    public class InterfaceStatus
    {
        [DataMember]
        public int ID { get; set; }

        [DataMember]
        public string StatusName { get; set; }

       
    }

    [DataContract]
    public class InterfaceRole
    {
        [DataMember]
        public int ID { get; set; }

        [DataMember]
        public string Role { get; set; }


    }

    [DataContract]
    public class InterfaceBlockedUser
    {
        [DataMember]
        public int ID { get; set; }

        [DataMember]
        public string Reason { get; set; }

        [DataMember]
        public int Email { get; set; }

        [DataMember]
        public DateTime DateFrom { get; set; }

        [DataMember]
        public DateTime DateTo { get; set; }

        [DataMember]
        public int SuspendedBy { get; set; }

        [DataMember]
        public InterfaceAdmin Banner { get; set; }

        [DataMember]
        public InterfaceUser UserObject { get; set; }

        [DataMember]
        public int UserId { get; set; }

       


    }
    [DataContract]
    public class InterfaceFlaggedUser
    {
        [DataMember]
        public int ID { get; set; }

        [DataMember]
        public string Reason { get; set; }

        [DataMember]
        public int FlaggedByUserId { get; set; }

        [DataMember]
        public int WhoIsFlaggedID { get; set; }


        [DataMember]
        public InterfaceUser FlaggedBy { get; set; }

        [DataMember]
        public InterfaceUser WhoIsFlagged { get; set; }
    }

    [DataContract]
    public class InterfaceAdmin
    {
        [DataMember]
        public int ID { get; set; }

        [DataMember]
        public string Username { get; set; }

        [DataMember]
        public string Email { get; set; }

    }
}
