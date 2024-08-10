using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace dotNetJustEat.Entities
{
    public class UserRegistry
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [ForeignKey("UserCredentials")]
        public string UserCredentialsId { get; set; }

        [Required]
        public string Name { get; set; }

        [Required]
        public string Surname { get; set; }

        [Required]
        public string Address { get; set; }

        [Required]
        public string City { get; set; }

        [Required]
        public string CAP { get; set; }

        [Required]
        public string MobileNumber { get; set; }

        // Navigation property

        public virtual UserCredentials UserCredentials { get; set; }
    }
}
