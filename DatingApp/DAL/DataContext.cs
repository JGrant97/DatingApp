using API.Models;
using Microsoft.EntityFrameworkCore;

namespace API.DAL
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions options) : base(options)
        {

        }

        public DbSet<AppUser> Users { get; set; }
    }
} 
