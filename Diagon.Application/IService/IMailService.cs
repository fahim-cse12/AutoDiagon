using Diagon.Application.Service.Common;

namespace Diagon.Application.IService
{
    public interface IMailService
    {
        void SendEmail(Message message);
    }
}
