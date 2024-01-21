using AngularAuthAPI.Models;
using System;
namespace AngularAuthAPI.UtilityServices
{
    public interface IEmailService
    {
        void SendEmail(EmailModel emailModel);
    }
}