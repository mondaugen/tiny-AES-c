AES_DIR=..
CFLAGS=-I$(AES_DIR)
LDFLAGS=-L$(AES_DIR)
LDLIBS=-laes -lc

simple_decryptor.bin : simple_decryptor.o
	gcc $(LDFLAGS) $^ -o $@ $(LDLIBS)

simple_decryptor.o : simple_decryptor.c $(AES_DIR)/aes.h aes_lib
	gcc -c $< $(CFLAGS) -o $@

aes_lib:
	make -C $(AES_DIR) libaes.a

example1: simple_decryptor.bin
	echo -ne "0123456789abcdef0123456789abcdef" | openssl enc -aes-128-ctr -K 00112233445566778899aabbccddeeff -iv ffeeddccbbaa99887766554433221100 | tee /tmp/hi | STYLE=CTR ./simple_decryptor.bin > /tmp/out && cat /tmp/out

clean:
	$(RM) simple_decryptor.o simple_decryptor.bin
