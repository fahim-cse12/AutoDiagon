using System.ComponentModel.DataAnnotations;

namespace Diagon.Domain
{
    public class Doctor : BaseEntity
    {

        [Required(ErrorMessage = "Please Enter Doctors Name")]
        public string DoctorName { get; set; }
        public string Gender { get; set; }
        public string? ContactNumber { get; set; }
        public decimal DoctorsFee { get; set; }
        public string? Email { get; set; }
        public string? SpecialistOn { get; set; }
        public string? ScheduleDays { get; set; }
        public TimeSpan? ScheduleTime { get; set; }
        public ICollection<Appointment> Appointments { get; set; }

    }
}
