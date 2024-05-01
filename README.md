# secure-file-transfer-project

Client-Server application, written in C++, that resembles a Cloud Storage. In this project all the security protocols (for authentication and data transmission) have been designed specifically for this project and have been implemented using OpenSSL. Each user has a “dedicated storage” on the server, and User A cannot access User B “dedicated storage". Users can Upload, Download, Rename, or Delete data to/from the Cloud Storage in a safe manner.