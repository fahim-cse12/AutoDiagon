using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace Diagon.Domain
{
    public class Appointment : BaseEntity
    {
        public int PatientId { get; set; }
        public int DoctorId { get; set; }
        public int InvestigationId { get; set; }
        public DateTime AppointmentDate { get; set; }
        public TimeSpan AppointmentTime { get; set; }

        public Patient Patient { get; set; }
        public Doctor Doctor { get; set; }
        public Investigation Investigations { get; set; }
        public InvestigationResult InvestigationResults { get; set; }
    }
}
