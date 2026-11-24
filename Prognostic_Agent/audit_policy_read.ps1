# Read-only native query; no audit-policy setter is exposed.
if (-not ('PrognosticAuditRead' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PrognosticAuditRead {
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AuditQuerySystemPolicy(ref Guid id, uint count, out IntPtr buffer);
    [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr buffer);
    public static int ProcessCreation() {
        Guid id = new Guid("0CCE922B-69AE-11D9-BED3-505054503030");
        IntPtr buffer;
        if (!AuditQuerySystemPolicy(ref id, 1, out buffer))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try { return Marshal.ReadInt32(buffer, 16); }
        finally { AuditFree(buffer); }
    }
}
'@
}
