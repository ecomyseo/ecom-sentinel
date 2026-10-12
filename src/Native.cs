using System.Net;
using System.Runtime.InteropServices;

namespace EcomSentinel;

/// <summary>Minimal P/Invoke: list TCP connections with their owning PID (IPv4).</summary>
public static class Native
{
    public sealed record TcpConn(int Pid, string RemoteIp, int RemotePort);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen,
        bool sort, int ipVersion, int tableClass, int reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    private static int DecodePort(uint raw)
        => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    public static List<TcpConn> GetTcpConnections()
    {
        var result = new List<TcpConn>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return result;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            uint ret = GetExtendedTcpTable(buffer, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return result;

            int count = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);
            int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                if (row.RemoteAddr == 0) continue; // not connected
                var ip = new IPAddress(BitConverter.GetBytes(row.RemoteAddr)).ToString();
                result.Add(new TcpConn((int)row.OwningPid, ip, DecodePort(row.RemotePort)));
            }
        }
        catch
        {
            // Never let connection enumeration crash the agent.
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return result;
    }
}
