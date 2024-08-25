# Certificate generator

_Self-signed certificates for your local network made simple._

All keys and generated certificates are owned by you. You are the only person responsible for keeping these secrets secure.

## Basic usage

1. Edit `certgen.toml` file.
  * Apply your desired defaults. Be mindful of setting the certificate validity - too long and it will be rejected by most browsers! 2 years seems safe.
  * Add your desired server names (and/or IP addresses).
2. Run the tool (e.g. `cargo run`)
3. Preserve key files and the `root_ca.crt` file. These files will be used to identify fingerprint of your servers and generate updated certificates
4. Deploy certificates to your devices
5. Install the `root_ca.crt` on your systems:
  * on OSX: 
    * Open Keychain > System > Certificates. 
    * Add certificate.
    * Double click on newly added certificate. Its name will match the name you configured in the `certgen.toml` file
    * Expand `Trust` and then `Allow all`
  * on Windows:
    * Right-click the `root_ca.crt` file
    * Select _Install Certificate_
    * Select either _Current User_ or _Local Machine_,
    * Select _Place in the following store_ > _Trusted Root Certification Authorities_
    * Continue to import
  * on Linux
    * Open the web browser you use daily
    * Open Settings > Security
    * Look for _Manage Certificates_
    * Import the `root_ca.crt` file, and make sure to trust it.
  * on Android
    * Download the `root_ca.crt` file
    * Open Settings, search for _CA Certificate_
    * Click _Install Anyway_
    * Select your certificate

## FAQs

### Why is everything warning me against installation?

This is because you are technically installing a certificate that has the power of "blessing" domains as "secure". Normally this is controlled by a set of _truly trusted_ set of Root Certifcate Authorities (CAs). Your self-generated CA is now joining the club, and it is granted the same capability as all the other, pre-selected Root CAs. If your `root_ca.key` leaks **your security will be compromised**, and the owner may generate certificates and impersonate any website they want. Because of this you have to keep all the keys in secure store.
