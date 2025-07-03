namespace Gp4Net.Tool.Services.CardCommunication
{
    /// <summary>
    /// Wrapper interface for APDU responses to enable unit testing.
    /// </summary>
    public interface IResponseWrapper
    {
        /// <summary>
        /// Gets the response data.
        /// </summary>
        byte[]? Data { get; }

        /// <summary>
        /// Gets the status word.
        /// </summary>
        ushort StatusWord { get; }
    }
}
