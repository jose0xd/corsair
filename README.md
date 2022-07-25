# Instrucciones
Ejecutar `python3 generate.py`

Este comando genera dos certificados 'cert1.pem' y 'cert2.pem', cuyos módulos comparten un factor común. También genera una contraseña cifrada en 'passwd.enc' con la clave privada asociada a ''cert1.pem', y un mensaje cifrado con esta contraseña en AES256 en 'encrypted_file.txt' 

- Sacar las claves públicas de los certificados y de estas los módulos y demás datos necesarios.
- Construir la clave privada asociada al 'cert1.pem'. Con esta clave privada desencriptar la contraseña simetrica encriptada en 'passwd.enc' (`openssl rsautl -decrypt -inkey key1.pem -in passwd.enc > passwd.txt`)
- Desencriptar el mensaje: `openssl enc -in encrypted_file.txt -out message.txt -d -aes256`
