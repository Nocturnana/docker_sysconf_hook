versioned_so = memory_hook.so


$(versioned_so): detection.c
	gcc -std=c99 -Wall -shared -g -fPIC -ldl detection.c -o $(versioned_so)
	

