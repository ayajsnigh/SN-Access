ServiceNow Access Troubleshooter

Install (Chrome or Edge)
1. Unzip this folder.
2. Open chrome://extensions (or edge://extensions) and turn on Developer mode.
3. Choose "Load unpacked" and select the unzipped folder.
4. Pin the extension from the puzzle-piece menu.

Use
1. Open any ServiceNow form (or list) in an instance where you are admin or security_admin.
2. Click the extension icon. The panel opens with the table and record already filled in.
3. Pick the user, the operation and, optionally, a field, then press "Check access".
4. Click the icon again to close the panel.

It works on any instance domain, because it only runs on the tab where you click the icon.

Limits
- Script ACLs are shown but not evaluated for another user (marked "?").
- Dynamic conditions (javascript: / DYNAMIC) are only evaluated when checking yourself.
- Needs read access to sys_security_acl, sys_security_acl_role, sys_user_has_role, sys_db_object and sys_dictionary.
- Verify new results against Impersonate + System Security > Debug Security Rules.
