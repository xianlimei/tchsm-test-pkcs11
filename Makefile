test: main.c tools.c pkcs11.h main.h tools.h
	gcc -o testPKCS11 main.c tools.c -ldl -lcrypto

