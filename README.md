# Radsec (RFC 6614) test tool
This is a windows executable test tool for testing Radsec (Radius over TLS).

RadSec is a fairly new protocol with the purpose of encrypting Radius traffic using mutual TLS. It uses TCP port 2083 for both authentication and accounting as opposed to standard radius which UDP 1812 for authentication and UDP 1813 for accounting.

The entire Radius packet is encrypted, making it safe to traverse untrusted networks. It otherwise serves the same purpose as the Radius protocol.

The tool was designed to assist with enabling Radsec on the RadiusStack platform (https://radius-stack.com) but is free for use by anyone for any purpose.

# Features
*Debug output for troubleshooting

*Profiles to save, export and import settings

*Multiple test types including Authentication, accountiong and full transaction (auth, acct-start, acct-interim, acct-stop)

*Performance testing - ability to set the number of transactions and worker threads

*Custom attributes - define attributes and value to be sent as part of the execution, with the ability to define static or random values.

# Support, feature requests and contribution
Please submit a github ticket if you need any assistance, would like a request a feature, or would like to contribute this this or any RadiusStack associated projects.

# References
Radsec-test-tool homepage - https://radsec.radius-stack.com

RadiusStack homepage - https://radius-stack.com
