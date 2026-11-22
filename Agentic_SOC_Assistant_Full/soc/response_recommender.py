"""Safe recommendations only. No host changes are executed by this module."""
def recommend_actions(event_id, risk_level):
    mapping = {
        4625: ["Review failed-login frequency and source IP","Check whether a successful logon followed","Consider account protection controls after approval"],
        4624: ["Verify user, logon type, source and expected working hours","Correlate with privilege and process events"],
        4672: ["Verify whether the account should hold special privileges","Review activity immediately before and after the event"],
        4688: ["Inspect process path, command line, parent process and signature","Correlate with endpoint protection alerts"],
        4720: ["Verify the account creation request and actor","Review initial logon and group membership"],
        4732: ["Verify the group change and affected group","Review actor privileges and change approval"],
        4740: ["Contact account owner through approved process","Review source systems causing lockouts"],
        1102: ["Preserve centralised logs and available evidence","Escalate for security investigation"],
        4697: ["Verify service installation authorisation","Inspect service binary, signer and startup configuration"],
        7045: ["Inspect service executable path and account","Compare with approved software deployment"]
    }
    actions = mapping.get(int(event_id), ["Collect additional host and network evidence","Escalate to an analyst for review"])
    if risk_level in ("High","Critical"):
        actions = ["Prioritise analyst review"] + actions
    return actions
