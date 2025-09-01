using System;

namespace Gp4Net.Domain.Keys;

public static partial class GpTestKeys
{
    /// <summary>
    /// Well-known test AIDs for development and testing.
    /// </summary>
    // @TODO: THESE ARE AIDs, NOT "TEST AIDS".
    public static class TestAids
    {
        /// <summary>
        /// Standard ISD AID.
        /// </summary>
        public static readonly byte[] IsdAid = Convert.FromHexString("A000000003000000");

        /// <summary>
        /// Common test application AID.
        /// </summary>
        public static readonly byte[] TestAppAid = Convert.FromHexString("A000000001020304");

        /// <summary>
        /// OpenFIPS201 applet AID.
        /// </summary>
        public static readonly byte[] OpenFips201Aid = Convert.FromHexString(
            "A000000308000010000100"
        );

        /// <summary>
        /// OpenFIPS201 package AID.
        /// </summary>
        public static readonly byte[] OpenFips201PackageAid = Convert.FromHexString(
            "A0000003080000100001"
        );
    }
}
