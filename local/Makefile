AES_DIR=..
CFLAGS=-I$(AES_DIR)
LDFLAGS=-L$(AES_DIR)
LDLIBS=-laes -lc

simple_decryptor.bin : simple_decryptor.o
	gcc $(LDFLAGS) $^ -o $@ $(LDLIBS)

simple_decryptor.o : simple_decryptor.c $(AES_DIR)/aes.h _common.h aes_lib
	gcc -c $< $(CFLAGS) -o $@

ctr_code.bin : ctr_code.o aes_128_ctr.o ctr_block_cipher.o
	gcc $(LDFLAGS) $^ -o $@ $(LDLIBS)

aes_128_ctr.o : aes_128_ctr.c ctr_block_cipher.h
	gcc -c $< $(CFLAGS) -o $@

ctr_block_cipher.o : ctr_block_cipher.c  
	gcc -c $< $(CFLAGS) -o $@

ctr_code.o : ctr_code.c $(AES_DIR)/aes.h _common.h aes_lib
	gcc -c $< $(CFLAGS) -o $@

aes_lib:
	make -C $(AES_DIR) libaes.a

example1: simple_decryptor.bin
	echo -ne "0123456789abcdef0123456789abcdef" | openssl enc -aes-128-ctr -K 00112233445566778899aabbccddeeff -iv ffeeddccbbaa99887766554433221100 | tee /tmp/hi | STYLE=CTR ./simple_decryptor.bin > /tmp/out && cat /tmp/out

example2: ctr_code.bin
	echo -ne "cool boy ya ya" | ./ctr_code.bin | openssl env -d -aes-128-ctr -K 1234123412341234 -iv 4321432143214321

clean:
	$(RM) simple_decryptor.o simple_decryptor.bin
