using System;
using System.Runtime.InteropServices;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Ldap;
using ADAssessment.Infrastructure.Sysvol;

namespace ADAssessment.Infrastructure.Smb
{
    /// <summary>
    /// Domain Controller'ın SMB protokolü seviyesindeki güvenlik davranışını, gerçek bir
    /// bağlantı denemesiyle tespit eden altyapı sınıfı. SysvolDataExtractor'ın SYSVOL
    /// paylaşımına bağlanmak için kullandığı aynı Windows API'sini (WNetAddConnection2 -
    /// net use'ın arka planda yaptığı şey, P/Invoke, ek NuGet paketi gerektirmez) kullanır;
    /// burada ayrı bir P/Invoke bildirimi tutulmuştur çünkü SYSVOL erişimi ile SMB güvenlik
    /// kontrolü kavramsal olarak bağımsız iki altyapı entegrasyonudur.
    /// </summary>
    public sealed class SmbProtocolSecurityChecker : ISmbProtocolSecurityChecker
    {
        private readonly LdapConnectionOptions _options;

        public SmbProtocolSecurityChecker(LdapConnectionOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            _options = options;
        }

        public SmbProtocolSecuritySettings CheckAnonymousAccess()
        {
            (string server, _) = SysvolDataExtractor.ParseServerAndDomain(_options.LdapPath);

            return new SmbProtocolSecuritySettings
            {
                DomainController = server,
                IsAnonymousAccessAllowed = IsAnonymousAccessAllowed(server)
            };
        }

        /// <summary>
        /// IPC$ (Inter-Process Communication - süreçler arası iletişim için ayrılmış
        /// özel SMB paylaşımı, null session testinin klasik hedefi) paylaşımına, kasıtlı
        /// olarak boş kullanıcı adı ve boş şifreyle bağlanmayı dener - "net use \\dc\ipc$
        /// "" /user:"""" komutunun yaptığı ile birebir aynı, çünkü o komut da arka planda
        /// aynı WNetAddConnection2 API'sini çağırır. Bağlantı başarılı olursa hemen
        /// kapatılır - kalıcı bir oturum bırakılmaz.
        /// </summary>
        private static bool IsAnonymousAccessAllowed(string server)
        {
            string ipcPath = $@"\\{server}\IPC$";
            var resource = new NETRESOURCE
            {
                dwType = ResourceTypeDisk,
                lpRemoteName = ipcPath
            };

            int result = WNetAddConnection2(ref resource, string.Empty, string.Empty, 0);

            bool succeeded = result == 0 || result == ErrorAlreadyAssigned;

            if (result == 0)
            {
                WNetCancelConnection2(ipcPath, 0, true);
            }

            return succeeded;
        }

        private const int ResourceTypeDisk = 0x00000001;
        private const int ErrorAlreadyAssigned = 85;

        [StructLayout(LayoutKind.Sequential)]
        private struct NETRESOURCE
        {
            public int dwScope;
            public int dwType;
            public int dwDisplayType;
            public int dwUsage;
            [MarshalAs(UnmanagedType.LPWStr)] public string? lpLocalName;
            [MarshalAs(UnmanagedType.LPWStr)] public string? lpRemoteName;
            [MarshalAs(UnmanagedType.LPWStr)] public string? lpComment;
            [MarshalAs(UnmanagedType.LPWStr)] public string? lpProvider;
        }

        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        private static extern int WNetAddConnection2(ref NETRESOURCE netResource, string password, string username, int flags);

        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        private static extern int WNetCancelConnection2(string name, int flags, bool force);
    }
}
