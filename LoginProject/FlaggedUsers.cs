//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace LoginProject
{
    using System;
    using System.Collections.Generic;
    
    public partial class FlaggedUsers
    {
        public int ID { get; set; }
        public string Reason { get; set; }
        public int FlaggedBy { get; set; }
        public int UserID { get; set; }
    
        public virtual Users Users { get; set; }
        public virtual Users Users1 { get; set; }
    }
}
