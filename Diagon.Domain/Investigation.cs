using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Diagon.Domain
{
    public class Investigation : BaseEntity
    {
        public string InvestigationName { get; set; }
        public string Description { get; set; }
        public decimal Cost { get; set; }
        public ICollection<Appointment> Appointments { get; set; }
    }
}
