# SecureChannel applet and host application

A Java Card applet with custom secure channel and an additional host application. 

This project was made for course [PV204 Security Technologies](https://is.muni.cz/course/fi/spring2020/PV204) @ [MUNI](https://www.muni.cz/)


### Team members:
* Mykhailo Klunko [(@klnmi97)](https://github.com/klnmi97)
* Vojtěch Šnajdr [(@aerchel)](https://github.com/aerchel)
* Daniel Zaťovič [(@danzatt)](https://github.com/danzatt)

### Implementation notes:
* User PIN is chosen when installing the applet
* To establish secure channel we use ECDH with SecP256k1 curve
* Public ECDH keys are then encrypted using AES and user PIN hashed with SHA-1 as a key
* Subsequent communication is encryped using shared ECDH secret
