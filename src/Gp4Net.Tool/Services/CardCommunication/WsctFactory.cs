using WSCT.Core.APDU;
using WSCT.ISO7816;

namespace Gp4Net.Tool.Services.CardCommunication
{
    /// <summary>
    /// Concrete implementation of IWsctFactory.
    /// </summary>
    public class WsctFactory : IWsctFactory
    {
        /// <inheritdoc />
        public ICardContextWrapper CreateCardContext()
        {
            return new WsctCardContextWrapper();
        }

        /// <inheritdoc />
        public ICardCommand CreateCommandApdu(byte[] command)
        {
            return new CommandAPDU(command);
        }

        /// <inheritdoc />
        public ICardResponse CreateResponseApdu()
        {
            return new ResponseAPDU();
        }
    }
}
