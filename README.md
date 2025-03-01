# Hybrid Kerberos Authentication System (HKS) with Java

This project implements a Hybrid Kerberos System (HKS), a network authentication protocol that ensures secure authentication over an insecure network. The system integrates both symmetric encryption (AES) and asymmetric encryption (RSA) to protect user credentials, session keys, and secure communication.

The Key Distribution Center (KDC) manages key exchanges, issues authentication tickets, and enables secure communication between clients and servers. The project is built in Java, utilizing Java’s crypto libraries and JavaFX for the user interface.

Key Features:
* Client & Server Registration – Clients and servers register with the Key Distribution Center (KDC), receiving unique public-private key pairs generated using RSA encryption.
* Secure Authentication – Clients authenticate by sending their ID and password to the KDC. Upon successful validation, the KDC generates an AES session key, encrypts it using RSA, and sends it as a ticket.
* Ticket Granting Mechanism – The KDC issues a session key ticket, which acts as proof of authentication, eliminating the need for constant password transmission.
* End-to-End Secure Communication – The AES session key is used for encryption between the client and the server, ensuring all messages remain private.
* Ticket Expiration & Renewal – Tickets expire after 5 minutes, requiring the client to request a new one, ensuring session security.
* Key Management – The KDC securely stores all cryptographic keys, manages key issuance, and prevents unauthorized access.

Implementation Details:
1. Client Module:
- Registers users by generating an RSA key pair.
- Requests authentication and receives an AES session key in an encrypted ticket.
- Uses the session key to communicate securely with the server.
2. Server Module:
- Registers with the KDC, receiving its own RSA key pair.
- Receives encrypted session keys and decrypts them using its private key.
- Verifies incoming messages using AES decryption.
3. Key Distribution Center (KDC):
- Manages public-private key generation.
- Authenticates clients and issues encrypted tickets containing session keys.
- Handles ticket expiration and renewal requests.
- Stores all authentication records in an encrypted dataset.csv file.

