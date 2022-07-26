USER = jarredon
LDFLAGS="-L/sgoinfre/goinfre/Perso/$(USER)/homebrew/Cellar/openssl@1.1/1.1.1o/lib"
CPPFLAGS="-I/sgoinfre/goinfre/Perso/$(USER)/homebrew/Cellar/openssl@1.1/1.1.1o/include"

all:
	gcc $(CPPFLAGS) $(LDFLAGS) -lssl -lcrypto -o corsair  main.c
