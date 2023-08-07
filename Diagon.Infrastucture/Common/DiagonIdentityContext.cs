using Diagon.Domain;
using Diagon.Domain.Users;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Diagon.Infrastucture.Common
{
    public class DiagonIdentityContext : IdentityDbContext<User>
    {      
        public DiagonIdentityContext(DbContextOptions<DiagonIdentityContext> options): base(options)
        {
            
        }
        //protected override void OnModelCreating(ModelBuilder modelBuilder)
        //{
        //    base.OnModelCreating(modelBuilder);
        //}
        public DbSet<Doctor> Doctors { get; set; }
        public DbSet<Patient> Patients { get; set; }
        public DbSet<Investigation> Investigations { get; set; }
        public DbSet<Appointment> Appointments { get; set; }
        public DbSet<InvestigationResult> InvestigationResults { get; set; }
    }
}
