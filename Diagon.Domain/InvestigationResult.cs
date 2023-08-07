using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Diagon.Domain
{
    public class InvestigationResult : BaseEntity
    {
        public int AppointmentId { get; set; }
        public string ResultDetails { get; set; }
        public DateTime ResultDate { get; set; }
        public Appointment Appointment { get; set; }
    }
}
