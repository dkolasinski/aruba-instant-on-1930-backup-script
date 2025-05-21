# aruba-instant-on-1930-backup-script

This is startup-configuration download script, for automated backups.

Works with:
* Aruba Instant ON 1930
* CISCO CBS350
* CISCO C1300

Works on Aruba and CISCO. It is allmost the same GUI.

### Requirements

- Perl
- LWP::Simple (Debian/Ubuntu: libwww-perl package)
- Crypt::OpenSSL::RSA (Debian/Ubuntu: libcrypt-openssl-rsa-perl package)

HTTPS connection to switch on port 443.

### Usage

As simple as:

```
./ofi-1930-get-backup.pl <ip/hostname> <user> <pass> <output filename>
```

### Examples

Proper execution:

```
./ofi-1930-get-backup.pl 10.10.10.10 admin some.password /tmp/download1
req 1. LOCATION REQ OK
req 2. INITIAL REQ OK:  CISCO CBS
req 3. RSA KEY REQ OK
req 3. LOGIN TOKEN REQ OK
req 3. PASSWORD ENCRYPT ENABLE REQ OK
req 4. LOGIN OK
req 5. DOWNLOAD OK
END OF SCRIPT, EXITING
```

Login failure:

```
./ofi-1930-get-backup.pl 10.10.10.10 admin some.password /tmp/download1
req 1. LOCATION REQ OK
req 2. INITIAL REQ OK:  CISCO CBS
req 3. RSA KEY REQ OK
req 3. LOGIN TOKEN REQ OK
req 3. PASSWORD ENCRYPT ENABLE REQ OK
req 4. LOGIN FAILED, RESPONSE: Bad User or Password
```
