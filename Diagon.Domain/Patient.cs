using System.ComponentModel.DataAnnotations;

namespace Diagon.Domain
{
    public class Patient : BaseEntity
    {      
        public string PatientName { get; set; }    
        public string PatientAddress { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string Gender { get; set; }
        public string ContactNumber { get; set; }
        public string? Email { get; set; }
        public bool IsNew { get; set; }
        public ICollection<Appointment> Appointments { get; set; }

    }
}
