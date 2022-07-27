#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#define CERT1 "cert1.pem"
#define CERT2 "cert2.pem"
#define PASSWD "passwd.enc"

void	oh_no(char *msg);
RSA		*get_public_key(char *cert_file);
void	get_prime_factors(RSA *pubkey1, RSA *pubkey2, BIGNUM **p, BIGNUM **q);
RSA		*generate_private_key(BIGNUM *p, BIGNUM *q);

int main()
{
	// Get private key1 from cert1 and cert2
	RSA	*pubkey1 = get_public_key(CERT1);
	RSA	*pubkey2 = get_public_key(CERT2);

	BIGNUM *p, *q;
	get_prime_factors(pubkey1, pubkey2, &p, &q);
	RSA *priv_key = generate_private_key(p, q);
	RSA_free(pubkey1);
	RSA_free(pubkey2);

	BIO *out_file = BIO_new_file("private_key.pem", "w");
	PEM_write_bio_RSAPrivateKey(out_file, priv_key, NULL, NULL, 0, NULL, NULL);
	BIO_free_all(out_file);

	// Show information about private key
	BIO *output = BIO_new_fp(stdout, BIO_NOCLOSE);
	RSA_print(output, priv_key, 0);
	PEM_write_bio_RSAPrivateKey(output, priv_key, NULL, NULL, 0, NULL, NULL);
	BIO_free_all(output);

	// Decrypt password with the private key
	int len = RSA_size(priv_key);
	int fd = open(PASSWD, O_RDONLY);
	unsigned char *en_passwd = malloc(len * sizeof(char));
	read(fd, en_passwd, len);
	close(fd);
	unsigned char *passwd = malloc(32 * sizeof(char)); // aes256 -> key = 32b
	for (int i = 0; i < 32; i++) passwd[i] = 0;

	int res = RSA_private_decrypt(len, (const unsigned char *)en_passwd,
			passwd, priv_key, RSA_PKCS1_PADDING);
	if (res == -1)
		printf("Error: cannot decrypt the password\n");
	else
	{
		passwd[res - 1] = '\0'; // \n at end of file
		printf("\n>> The password is: %s\n", passwd);
		printf("Use this command to decrypt the message:\n"
			"'openssl enc -in encrypted_file.txt -out message.txt -d -aes256'\n");
	}
	
	free(en_passwd); free(passwd);
	RSA_free(priv_key); // p and q are inside priv_key
}

void	oh_no(char *msg)
{
	fprintf(stderr, "%s", msg);
	exit(-1);
}

RSA	*get_public_key(char *cert_file)
{
	X509		*cert;
	EVP_PKEY	*pubkey;
	RSA			*pubkey_rsa;
	BIO 		*in_file = BIO_new_file(cert_file, "r");

	if (!in_file)
		oh_no("Error: cannot open file\n");
	cert = PEM_read_bio_X509(in_file, NULL, NULL, NULL);
	if (!cert)
		oh_no("Error: cannot read file\n");
	BIO_free_all(in_file);

	pubkey = X509_get_pubkey(cert);
	if (!pubkey)
		oh_no("Error: cannot get public key from certificate\n");
	X509_free(cert);
	pubkey_rsa = EVP_PKEY_get1_RSA(pubkey);
	EVP_PKEY_free(pubkey);

	return (pubkey_rsa);
}

void	get_prime_factors(RSA *pubkey1, RSA *pubkey2, BIGNUM **p, BIGNUM **q)
{
	const BIGNUM *n1 = RSA_get0_n(pubkey1);
	const BIGNUM *n2 = RSA_get0_n(pubkey2);
	BN_CTX		 *ctx = BN_CTX_new();

	BN_CTX_start(ctx);
	BIGNUM *gcd = BN_CTX_get(ctx);
	BIGNUM *div = BN_CTX_get(ctx);
	BN_gcd(gcd, n1, n2, ctx);
	if (BN_is_one(gcd))
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		oh_no("There is no vulnerability, no common factors\n");
	}
	BN_div(div, NULL, n1, gcd, ctx);

	*p = BN_dup(gcd);
	*q = BN_dup(div);

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
}

RSA	*generate_private_key(BIGNUM *p, BIGNUM *q)
{
	RSA		*priv_key = RSA_new();
	BN_CTX	*ctx = BN_CTX_new();

	BN_CTX_start(ctx);
	BIGNUM *n = BN_CTX_get(ctx);
	BIGNUM *e = BN_new(); BN_hex2bn(&e, "10001");
	BIGNUM *one = BN_new(); BN_hex2bn(&one, "1");
	BIGNUM *phi_p = BN_new(); BN_sub(phi_p, p, one);
	BIGNUM *phi_q = BN_new(); BN_sub(phi_q, q, one);
	BIGNUM *d = BN_CTX_get(ctx);
	BIGNUM *e1 = BN_CTX_get(ctx);
	BIGNUM *e2 = BN_CTX_get(ctx);
	BIGNUM *coef = BN_CTX_get(ctx);

	BN_mul(n, p, q, ctx);
	BN_mul(d, phi_p, phi_q, ctx);
	BN_mod_inverse(d, e, d, ctx);
	BN_mod(e1, d, phi_p, ctx);
	BN_mod(e2, d, phi_q, ctx);
	BN_sub(phi_p, phi_p, one);
	BN_mod_exp(coef, q, phi_p, p, ctx);
	
	RSA_set0_key(priv_key, BN_dup(n), e, BN_dup(d));
	RSA_set0_factors(priv_key, p, q);
	RSA_set0_crt_params(priv_key, BN_dup(e1), BN_dup(e2), BN_dup(coef));

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return (priv_key);
}
