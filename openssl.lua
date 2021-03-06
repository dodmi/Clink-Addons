--[[

What is this?
This is a definition file for command completion in Clink.

How to use this file?
- Run 'clink info'
- Place the file in one of the script locations
- Restart clink
- Now you should have tab completion for openssl parameters

Where do I get the latest version?
https://github.com/dodmi/Clink-Addons/tree/master/

When was this file updated?
2021-03-06

]]--

local parser = clink.arg.new_parser
local openssl_parser = parser({
    "asn1parse" .. parser({}, -- empty {}: don't suggest any positional args
        "-help", "-i", "-noout", "-dump", "-strictpem",
		"-offset",		-- Parameter +int file offset
		"-length",		-- Parameter +int length of section
		"-dlimit",		-- Parameter dump +int the first unknown bytes
		"-strparse", 	-- Parameter +int string offset
		"-genstr", 		-- Parameter string to generate ASN1 structure from
		"-item", 		-- Parameter string, item to parse
		"-inform" .. parser({"PEM", "DER"}),
	    "-in" .. parser({clink.filematches}),  		-- Parameter input file
		"-out" .. parser({clink.filematches}), 		-- Parameter output file
		"-oid" .. parser({clink.filematches}), 		-- Parameter additional oid definitions file
		"-genconf" .. parser({clink.filematches}) 	-- Parameter file to generate ASN1 structure from
	),
	"ca" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-verbose", "-utf8", "-create_serial", "-rand_serial",
		"-multivalue-rdn", "-selfsign", "-notext", "-batch", "-preserveDN",
		"-noemailDN", "-gencrl", "-msie_hack", "-infiles", "-updatedb",
		"-name", 				-- Parameter The particular CA definition to use
		"-subj", 				-- Parameter Use arg instead of request's subject
		"-startdate", 			-- Parameter Cert notBefore, YYMMDDHHMMSSZ
		"-enddate", 			-- Parameter YYMMDDHHMMSSZ cert notAfter (overrides -days)
		"-days", 				-- Parameter Number of days to certify the cert for
		"-policy", 				-- Parameter The CA 'policy' to support
		"-key", 				-- Parameter Key to decode the private key if it is encrypted
		"-sigopt", 				-- Parameter Signature parameter in n:v form
		"-crldays",				-- Parameter Days until the next CRL is due
		"-crlhours", 			-- Parameter Hours until the next CRL is due
		"-crlsec", 				-- Parameter Seconds until the next CRL is due
		"-valid", 				-- Parameter Add a Valid(not-revoked) DB entry about a cert (given in file)
		"-extensions",			-- Parameter Extension section (override value in config file)
		"-status", 				-- Parameter Shows cert status given the serial number
		"-crlexts", 			-- Parameter CRL extension section (override value in config file)
		"-crl_reason", 			-- Parameter revocation reason
		"-crl_hold", 			-- Parameter the hold instruction, an OID. Sets revocation reason to certificateHold
		"-crl_compromise", 		-- Parameter sets compromise time to val and the revocation reason to keyCompromise
		"-crl_CA_compromise",	-- Parameter sets compromise time to val and the revocation reason to CACompromise
		"-engine",				-- Parameter Use engine, possibly a hardware device
		"-passin",				-- Parameter Input file pass phrase source
 		"-md" .. parser({"md2", "md5", "sha", "sha1"}),
 		"-keyform" .. parser({"PEM", "ENGINE"}),
		"-config" .. parser({clink.filematches}),		-- Parameter config file
		"-keyfile" .. parser({clink.filematches}),		-- Parameter Private key
		"-cert" .. parser({clink.filematches}), 		-- Parameter The CA cert
		"-in" .. parser({clink.filematches}), 			-- Parameter The input PEM encoded cert request(s)
		"-out" .. parser({clink.filematches}), 			-- Parameter Where to put the output file(s)
		"-ss_cert" .. parser({clink.filematches}), 		-- Parameter File contains a self signed cert to sign
		"-spkac" .. parser({clink.filematches}), 		-- Parameter File contains DN and signed public key and challenge
		"-revoke" .. parser({clink.filematches}), 		-- Parameter Revoke a cert (given in file)
		"-extfile" .. parser({clink.filematches}), 		-- Parameter Configuration file with X509v3 extensions to add
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}), 	-- Parameter Write random data to the specified file
		"-outdir" .. parser({clink.dirmatches}) 		-- Parameter Where to put output cert
	),
	"ciphers" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-v", "-V", "-s", "-tls1", "-tls1_1", "-tls1_2",
		"-tls1_3", "-stdname", "-psk", "-srp",
		"-convert", 		-- Parameter Convert standard name into OpenSSL name
		"-ciphersuites" 	-- Parameter Configure the TLSv1.3 ciphersuites to use
	),
	"cms" .. parser(parser({clink.filematches}),
		"-help", "-encrypt", "-decrypt", "-sign", "-sign_receipt",
		"-resign", "-verify", "-verify_retcode", "-cmsout",
		"-data_out", "-data_create", "-digest_verify", "-digest_create",
		"-compress", "-uncompress", "-EncryptedData_decrypt",
		"-EncryptedData_encrypt", "-debug_decrypt", "-text",
		"-asciicrlf", "-nointern", "-noverify", "-nocerts", "-noattr",
		"-nodetach", "-nosmimecap", "-binary", "-keyid", "-nosigs",
		"-no_content_verify", "-no_attr_verify", "-stream", "-indef",
		"-noindef", "-crlfeol", "-noout", "-receipt_request_print",
		"-receipt_request_all", "-receipt_request_first", "-no-CAfile",
		"-no-CApath", "-print", "-*", "-ignore_critical", "-issuer_checks",
		"-crl_check", "-crl_check_all", "-policy_check", "-explicit_policy",
		"-inhibit_any", "-inhibit_map", "-x509_strict", "-extended_crl",
		"-use_deltas", "-policy_print", "-check_ss_sig", "-trusted_first",
		"-suiteB_128_only", "-suiteB_128", "-suiteB_192", "-partial_chain",
		"-no_alt_chains", "-no_check_time", "-allow_proxy_certs",
		"-aes128-wrap", "-aes192-wrap", "-aes256-wrap", "-des3-wrap",
		"-secretkey",				-- Parameter val
		"-secretkeyid",				-- Parameter val
		"-pwri_password",			-- Parameter val
		"-econtent_type",			-- Parameter val
		"-to",						-- Parameter To address
		"-from",					-- Parameter From address
		"-subject",					-- Parameter Subject
		"-signer",					-- Parameter Signer certificate file
		"-md",						-- Parameter Digest algorithm to use when signing or resigning
		"-keyopt",					-- Parameter Set public key parameters as n:v pairs
		"-receipt_request_from",	-- Parameter val
		"-receipt_request_to",		-- Parameter val
		"-policy",					-- Parameter adds policy to the acceptable policy set
		"-purpose",					-- Parameter certificate chain purpose
		"-verify_name",				-- Parameter verification policy name
		"-verify_depth",			-- Parameter chain depth limit
		"-auth_level",				-- Parameter chain authentication security level
		"-attime",					-- Parameter verification epoch time
		"-verify_hostname",			-- Parameter expected peer hostname
		"-verify_email",			-- Parameter expected peer email
		"-verify_ip",				-- Parameter expected peer IP address
		"-engine",					-- Parameter Use engine e, possibly a hardware device
		"-passin", 					-- Parameter Input file pass phrase source
		"-inform" .. parser({"SMIME", "PEM", "DER"}),
		"-outform" .. parser({"SMIME", "PEM", "DER"}),
		"-rctform" .. parser({"PEM", "DER"}),
		"-keyform" .. parser({"PEM", "ENGINE"}),
		"-in infile" .. parser({clink.filematches}), 		-- Parameter Input file
		"-out" .. parser{clink.filematches}, 				-- Parameter Output file
		"-verify_receipt" .. parser{clink.filematches}, 	-- Parameter infile
		"-certfile" .. parser{clink.filematches}, 			-- Parameter Other certificates file
		"-CAfile" .. parser{clink.filematches}, 			-- Parameter Trusted certificates file
		"-recip" .. parser{clink.filematches}, 				-- Parameter Recipient cert file for decryption
		"-certsout" .. parser{clink.filematches}, 			-- Parameter Certificate output file
		"-inkey" .. parser{clink.filematches}, 				-- Parameter Input private key (if not signer or recipient)
		"-rand" .. parser{clink.filematches}, 				-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches}, 			-- Parameter Write random data to the specified file
		"-content" .. parser{clink.filematches}, 			-- Parameter Supply or override content for detached signature
		"-CApath" .. parser{clink.dirmatches} 				-- Parameter trusted certificates directory
	),
	"crl" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-issuer", "-lastupdate", "-nextupdate", "-noout",
		"-fingerprint", "-crlnumber", "-badsig", "-no-CAfile",
		"-no-CApath", "-verify", "-text", "-hash", "-*", "-hash_old",
		"-nameopt",			-- Parameter Various certificate name options
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER"}),
		"-keyform" .. parser({"PEM", "ENGINE"}),
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file - default stdin
		"-out" .. parser{clink.filematches}, 		-- Parameter output file - default stdout
		"-key" .. parser{clink.filematches}, 		-- Parameter CRL signing Private key to use
		"-gendelta" .. parser{clink.filematches}, 	-- Parameter Other CRL to compare/diff to the Input one
		"-CAfile" .. parser{clink.filematches}, 	-- Parameter Verify CRL using certificates in file name
		"-CApath" .. parser{clink.dirmatches}	 	-- Parameter Verify CRL using certificates in dir
	),
	"crl2pkcs7" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-nocrl",
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file
		"-certfile" .. parser{clink.filematches}	-- Parameter File of chain of certs to a trusted CA
	),
	"dgst" .. parser(
		parser{clink.filematches},
		"-help", "-list", "-c", " -r", "-hex", "-binary", "-d",
		"-debug", "-fips-fingerprint", "-*", "-engine_impl",
		"-hmac",		-- Parameter Create hashed MAC with key
		"-mac",			-- Parameter Create MAC (not necessarily HMAC)
		"-sigopt",		-- Parameter Signature parameter in n:v form
		"-macopt",		-- Parameter MAC algorithm parameters in n:v form or key
		"-engine",		-- Parameter Use engine e, possibly a hardware device
		"-passin", 		-- Parameter Input file pass phrase source
		"-signature", 	-- Parameter File with signature to verify
		"-keyform" .. parser({"PEM", "ENGINE"}),
		"-out" .. parser{clink.filematches}, 		-- Parameter Output to filename rather than stdout
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches}, 	-- Parameter Write random data to the specified file
		"-sign" .. parser{clink.filematches}, 		-- Parameter Sign digest using private key
		"-verify" .. parser{clink.filematches}, 	-- Parameter Verify a signature using public key
		"-prverify" .. parser{clink.filematches} 	-- Parameter Verify a signature using private key
	),
	"dhparam" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-check", "-text", "-noout", "-C", "-2", "-5", "-dsaparam",
		"-engine",		-- Parameter Use engine e, possibly a hardware device
		"-inform" .. parser({"PEM", "DER"}),
 		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches} 	-- Parameter Write random data to the specified file
	),
	"dsa" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-noout", "-text", "-modulus", "-pubin", "-pubout",
		"-*", "-pvk-strong", "-pvk-weak", "-pvk-none",
		"-inform" .. parser({"PEM", "DER", "PVK"}),
		"-outform" .. parser({"PEM", "DER", "PVK"}),
		"-engine",	-- Parameter Use engine e, possibly a hardware device
		"-passout",	-- Parameter Output file pass phrase source
		"-passin", 	-- Parameter Input file pass phrase source
		"-in" .. parser{clink.filematches}, 		-- Parameter Input key
		"-out" .. parser{clink.filematches} 		-- Parameter Output file
	),
	"dsaparam" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-text", "-C", "-noout", "-genkey",
		"-engine",		-- Parameter Use engine e, possibly a hardware device
		"-inform" .. parser({"PEM", "DER"}),
 		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches} 	-- Parameter Write random data to the specified file
	),
	"ec" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-noout", "-text", "-param_out", "-pubin",
		"-pubout", "-no_public", "-check", "-*",
		"-param_enc",	-- Parameter Specifies the way the ec parameters are encoded
		"-conv_form",	-- Parameter Specifies the point conversion form
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-passout", 	-- Parameter Output file pass phrase source
		"-passin", 		-- Parameter Input file pass phrase source
		"-inform" .. parser({"PEM", "DER"}),
 		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file
		"-out" .. parser{clink.filematches} 		-- Parameter Output file
	),
	"ecparam" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-text", "-C", "-check", "-list_curves",
		"-no_seed", "-noout", "-genkey",
		"-name",		-- Parameter Use the ec parameters with specified 'short name'
		"-conv_form",	-- Parameter Specifies the point conversion form
		"-param_enc",	-- Parameter Specifies the way the ec parameters are encoded
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-inform" .. parser({"PEM", "DER"}),
 		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file  - default stdin
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file - default stdout
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches} 	-- Parameter Write random data to the specified file
	),
	"enc" .. parser({}, -- empty {}: don't suggest any positional args
		"-help","-list", "-ciphers", "-e", "-d", "-p", "-P", "-v", "-nopad",
		"-salt", "-nosalt", "-debug", "-a", "-base64", "-A", "-pbkdf2", "-none", "-*",
		"-pass",	-- Parameter Passphrase source
		"-bufsize",	-- Parameter Buffer size
		"-k",		-- Parameter Passphrase
		"-K",		-- Parameter Raw key, in hex
		"-S",		-- Parameter Salt, in hex
		"-iv",		-- Parameter IV in hex
		"-md",		-- Parameter Use specified digest to create a key from the passphrase
		"-iter", 	-- Parameter Specify the iteration count and force use of PBKDF2
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file
		"-kfile" .. parser{clink.filematches}, 		-- Parameter Read passphrase from file
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches} 	-- Parameter Write random data to the specified file
	),
	"engine" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-v", "-vv", "-vvv", "-vvvv", "-c", "-t", "-tt",
		"-pre",		-- Parameter Run command against the ENGINE before loading it
		"-post"	-- Parameter Run command against the ENGINE after loading it
	),
	"errstr" .. parser({}, -- empty {}: don't suggest any positional args
		"-help"
	),
	"gendsa" .. parser(
		parser{clink.filematches},
		"-help", "-*",
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-passout", -- Parameter Output file pass phrase source
		"-out" .. parser{clink.filematches}, 		-- Parameter Output the key to the specified file
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches} 	-- Parameter Write random data to the specified file
	),
	"genpkey" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-genparam", "-text", "-*",
		"-algorithm",	-- Parameter The public key algorithm
		"-pkeyopt",		-- Parameter Set the public key algorithm option as opt:value
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-pass", 		-- Parameter Output file pass phrase source
		"-outform" .. parser({"PEM", "DER"}),
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file
		"-paramfile" .. parser{clink.filematches} 	-- Parameter Parameters file
	),
	"genrsa" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-3", "-F4", "-f4", "-*",
		"-passout",	-- Parameter Output file pass phrase source
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-primes",	-- Parameter Specify number of primes
 		"-out" .. parser{clink.filematches}, 		-- Parameter Output the key to specified file
 		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
 		"-writerand" .. parser{clink.filematches} 	-- Parameter Write random data to the specified file
	),
	"help" .. parser({} -- empty {}: don't suggest any positional args
	),
	"list" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-1", "-commands", "-digest-commands", "-digest-algorithms",
		"-cipher-commands", "-cipher-algorithms", "-public-key-algorithms",
		"-public-key-methods", "-disabled", "-missing-help",
		"-options"		-- Parameter List options for specified command
	),
	"nseq" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-toseq",
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file
		"-out" .. parser{clink.filematches} 		-- Parameter Output file
	),
	"ocsp" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-ignore_err", "-noverify", "-nonce", "-no_nonce", "-resp_no_certs",
		"-resp_key_id", "-no_certs", "-no_signature_verify", "-no_cert_verify",
		"-no_chain", "-no_cert_checks", "-no_explicit", "-trust_other", "-no_intern",
		"-badsig", "-text", "-req_text", "-resp_text", "-no-CAfile", "-no-CApath",
		"-*", "-ignore_critical", "-issuer_checks", "-crl_check", "-crl_check_all",
		"-policy_check", "-explicit_policy", "-inhibit_any", "-inhibit_map",
		"-x509_strict", "-extended_crl", "-use_deltas", "-policy_print", "-check_ss_sig",
		"-trusted_first", "-suiteB_128_only", "-suiteB_128", "-suiteB_192", "-partial_chain",
		"-no_alt_chains", "-no_check_time", "-allow_proxy_certs",
		"-timeout",			-- Parameter Connection timeout (in seconds) to the OCSP responder
		"-url",				-- Parameter Responder URL
		"-host",			-- Parameter TCP/IP hostname:port to connect to
		"-port",			-- Parameter Port to run responder on
		"-validity_period",	-- Parameter Maximum validity discrepancy in seconds
		"-status_age",		-- Parameter Maximum status age in seconds
		"-path",			-- Parameter Path to use in OCSP request
		"-serial",			-- Parameter Serial number to check
		"-nmin",			-- Parameter Number of minutes before next update
		"-nrequest",		-- Parameter Number of requests to accept (default unlimited)
		"-ndays",			-- Parameter Number of days before next update
		"-rmd",				-- Parameter Digest Algorithm to use in signature of OCSP response
		"-rsigopt",			-- Parameter OCSP response signature parameter in n:v form
		"-header",			-- Parameter key=value header to add
		"-policy",			-- Parameter adds policy to the acceptable policy set
		"-purpose",			-- Parameter certificate chain purpose
		"-verify_name",		-- Parameter verification policy name
		"-verify_depth",	-- Parameter chain depth limit
		"-auth_level",		-- Parameter chain authentication security level
		"-attime",			-- Parameter verification epoch time
		"-verify_hostname",	-- Parameter expected peer hostname
		"-verify_email",	-- Parameter expected peer email
		"-verify_ip",		-- Parameter expected peer IP address
		"-out" .. parser{clink.filematches}, 			-- Parameter Output filename
		"-reqin" .. parser{clink.filematches}, 			-- Parameter File with the DER-encoded request
		"-respin" .. parser{clink.filematches}, 		-- Parameter File with the DER-encoded response
		"-signer" .. parser{clink.filematches}, 		-- Parameter Certificate to sign OCSP request with
		"-VAfile" .. parser{clink.filematches}, 		-- Parameter Validator certificates file
		"-sign_other" .. parser{clink.filematches}, 	-- Parameter Additional certificates to include in signed request
		"-verify_other" .. parser{clink.filematches},	-- Parameter Additional certificates to search for signer
		"-CAfile" .. parser{clink.filematches}, 		-- Parameter Trusted certificates file
		"-CApath" .. parser{clink.filematches}, 		-- Parameter Trusted certificates directory
		"-signkey" .. parser{clink.filematches}, 		-- Parameter Private key to sign OCSP request with
		"-reqout" .. parser{clink.filematches}, 		-- Parameter Output file for the DER-encoded request
		"-respout" .. parser{clink.filematches}, 		-- Parameter Output file for the DER-encoded response
		"-issuer" .. parser{clink.filematches}, 		-- Parameter Issuer certificate
		"-cert" .. parser{clink.filematches}, 			-- Parameter Certificate to check
		"-index" .. parser{clink.filematches}, 			-- Parameter Certificate status index file
		"-CA" .. parser{clink.filematches}, 			-- Parameter CA certificate
		"-rsigner" .. parser{clink.filematches}, 		-- Parameter Responder certificate to sign responses with
		"-rkey" .. parser{clink.filematches}, 			-- Parameter Responder key to sign responses with
		"-rother" .. parser{clink.filematches} 			-- Parameter Other certificates to include in response
	),
	"passwd" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-noverify", "-quiet", "-table", "-reverse", "-stdin", "-6", "-5", "-apr1", "-1", "-aixmd5", "-crypt",
		"-salt",	-- Parameter Use provided salt
		"-in" .. parser{clink.filematches}, 			-- Parameter Read passwords from file
		"-rand" .. parser{clink.filematches}, 			-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches} 		-- Parameter Write random data to the specified file
	),
	"pkcs12" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-nokeys", "-keyex", "-keysig", "-nocerts", "-clcerts",
		"-cacerts", "-noout", "-info", "-chain", "-twopass", "-nomacver", "-descert", "-export", "-noiter",  "-maciter", "-nomaciter", "-nomac", "-LMK", "-nodes", "-no-CAfile", "-no-CApath", "-*",
		"-certpbe",	-- Parameter Certificate PBE algorithm (default RC2-40)
		"-macalg",	-- Parameter Digest algorithm used in MAC (default SHA1)
		"-keypbe",	-- Parameter Private key PBE algorithm (default 3DES)
		"-inkey",	-- Parameter Private key if not infile
		"-name",	-- Parameter Use name as friendly name
		"-CSP",		-- Parameter Microsoft CSP name
		"-caname",	-- Parameter Use name as CA friendly name (can be repeated)
		"-passin",	-- Parameter Input file pass phrase source
		"-passout",	-- Parameter Output file pass phrase source
		"-password",-- Parameter Set import/export password source
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into random number generator
		"-writerand" .. parser{clink.filematches}, 	-- Parameter Write random data to the specified file
		"-certfile" .. parser{clink.filematches}, 	-- Parameter Load certs from file
		"-in" .. parser{clink.filematches}, 		-- Parameter Input filename
		"-out" .. parser{clink.filematches}, 		-- Parameter Output filename
		"-CAfile" .. parser{clink.filematches}, 	-- Parameter PEM-format file of CA's
		"-CApath" .. parser{clink.dirmatches} 		-- Parameter PEM-format directory of CA's
	),
	"pkcs7" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-noout", "-text", "-print", "-print_certs",
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser{clink.filematches}, 	-- Parameter Input file
		"-out" .. parser{clink.filematches} 	-- Parameter Output file
	),
	"pkcs8" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-topk8", "-noiter", "-nocrypt", "-scrypt", "-traditional",
		"-scrypt_N",	-- Parameter Set scrypt N parameter
		"-scrypt_r",	-- Parameter Set scrypt r parameter
		"-scrypt_p",	-- Parameter Set scrypt p parameter
		"-v2",			-- Parameter Use PKCS#5 v2.0 and cipher
		"-v1",			-- Parameter Use PKCS#5 v1.5 and cipher
		"-v2prf",		-- Parameter Set the PRF algorithm to use with PKCS#5 v2.0
		"-iter",		-- Parameter Specify the iteration count
		"-passin",		-- Parameter Input file pass phrase source
		"-passout",		-- Parameter Output file pass phrase source
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches} 	-- Parameter Write random data to the specified file
	),
	"pkey" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-pubin", "-pubout", "-text_pub", "-text", "-noout", "-*", "-traditional", "-check", "-pubcheck",
		"-passin",	-- Parameter Input file pass phrase source
		"-passout",	-- Parameter Output file pass phrase source
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser{clink.filematches}, 		-- Parameter Input key
		"-out" .. parser{clink.filematches} 		-- Parameter Output file
	),
	"pkeyparam" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-text", "-noout", "-check",
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file
		"-out" .. parser{clink.filematches} 		-- Parameter Output file
	),
	"pkeyutl" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-pubin", "-certin", "-asn1parse", "-hexdump", "-sign",
		"-verify", "-verifyrecover", "-rev", "-encrypt", "-decrypt",
		"-derive", "-engine_impl",
		"-kdf",		-- Parameter Use KDF algorithm
		"-kdflen",	-- Parameter KDF algorithm output length
		"-passin",	-- Parameter Input file pass phrase source
		"-pkeyopt",	-- Parameter Public key options as opt:value
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-peerform" .. parser({"PEM", "DER", "ENGINE"}),
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file - default stdin
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file - default stdout
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches}, 	-- Parameter Write random data to the specified file
		"-sigfile" .. parser{clink.filematches}, 	-- Parameter Signature file (verify operation only)
		"-inkey" .. parser{clink.filematches}, 		-- Parameter Input private key file
		"-peerkey" .. parser{clink.filematches} 	-- Parameter Peer key file used in key derivation
	),
	"prime" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-hex", "-generate", "-safe",
		"-bits",	-- Parameter Size of number in bits
		"-checks"	-- Parameter Number of checks
	),
	"rand" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-base64", "-hex",
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches} 	-- Parameter Write random data to the specified file
	),
	"rehash" .. parser({}, -- empty {}: don't suggest any positional args
		"-help"
	),
	"req" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-pubkey", "-new", "-batch", "-newhdr", "-modulus",
		"-verify", "-nodes", "-noout", "-verbose", "-utf8", "-text",
		"-x509", "-subject", "-multivalue-rdn", "-precert", "-*",
		"-key",				-- Parameter Private key to use
		"-keyform",			-- Parameter Key file format
		"-passin",			-- Parameter Private key password source
		"-passout",			-- Parameter Output file pass phrase source
		"-newkey",			-- Parameter Specify as type:bits
		"-pkeyopt",			-- Parameter Public key options as opt:value
		"-sigopt",			-- Parameter Signature parameter in n:v form
		"-nameopt",			-- Parameter Various certificate name options
		"-reqopt",			-- Parameter Various request text options
		"-subj",			-- Parameter Set or modify request subject
		"-days",			-- Parameter Number of days cert is valid for
		"-set_serial",		-- Parameter Serial number to use
		"-addext",			-- Parameter Additional cert extension key=value pair (may be given more than once)
		"-extensions",		-- Parameter Cert extension section (override value in config file)
		"-reqexts",			-- Parameter Request extension section (override value in config file)
		"-engine",			-- Parameter Use engine, possibly a hardware device
		"-keygen_engine",	-- Parameter Specify engine to be used for key generation operations
		"-inform" .. parser({"PEM", "DER"}),
 		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file
		"-config" .. parser{clink.filematches}, 	-- Parameter Request template file
		"-keyout" .. parser{clink.filematches}, 	-- Parameter File to send the key to
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches} 	-- Parameter Write random data to the specified file
	),
	"rsa" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-pubin", "-pubout", "-RSAPublicKey_in", "-RSAPublicKey_out",
		"-noout", "-text", "-modulus", "-check", "-*", "-pvk-strong",
		"-pvk-weak", "-pvk-none",
		"-passout",	-- Parameter Output file pass phrase source
		"-passin",	-- Parameter Input file pass phrase source
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER", "PVK"}),
		"-in" .. parser{clink.filematches}, 	-- Parameter Input file
		"-out" .. parser{clink.filematches} 	-- Parameter Output file
	),
	"rsautl" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-pubin", "-certin", "-ssl", "-raw", "-pkcs", "-oaep",
		"-sign", "-verify", "-asn1parse", "-hexdump", "-x931", "-rev",
		"-encrypt", "-decrypt",
		"-passin",	-- Parameter Input file pass phrase source
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file
		"-inkey" .. parser{clink.filematches}, 		-- Parameter Input key
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches} 	-- Parameter Write random data to the specified file
	),
	"s_client" .. parser({}, -- empty {}: don't suggest any positional args
		"-help","-4", "-6", "-no-CAfile", "-no-CApath", "-dane_ee_no_namechecks",
		"-reconnect", "-showcerts", "-debug", "-msg", "-msgfile outfile",
		"-nbio_test", "-state", "-crlf", "-quiet", "-ign_eof", "-no_ign_eof",
		"-fallback_scsv", "-crl_download", "-verify_return_error", "-verify_quiet",
		"-brief", "-prexit", "-security_debug", "-security_debug_verbose",
		"-build_chain", "-nocommands", "-noservername", "-tlsextdebug", "-status",
		"-async", "-no_ssl3", "-no_tls1", "-no_tls1_1", "-no_tls1_2", "-no_tls1_3",
		"-bugs", "-no_comp", "-comp", "-no_ticket", "-serverpref",
		"-legacy_renegotiation", "-no_renegotiation", "-legacy_server_connect",
		"-no_resumption_on_reneg", "-no_legacy_server_connect", "-allow_no_dhe_kex",
		"-prioritize_chacha", "-strict", "-debug_broken_protocol", "-no_middlebox",
		"-ignore_critical", "-issuer_checks", "-crl_check", "-crl_check_all",
		"-policy_check", "-explicit_policy", "-inhibit_any", "-inhibit_map",
		"-x509_strict", "-extended_crl", "-use_deltas", "-policy_print",
		"-check_ss_sig", "-trusted_first", "-suiteB_128_only", "-suiteB_128",
		"-suiteB_192", "-partial_chain", "-no_alt_chains", "-no_check_time",
		"-allow_proxy_certs", "-xchain_build", "-tls1", "-tls1_1", "-tls1_2",
		"-tls1_3", "-dtls", "-timeout", "-dtls1", "-dtls1_2", "-nbio", "-srp_lateuser",
		"-srp_moregroups", "-ct", "-noct", "-enable_pha",
		"-host",				-- Parameter Use -connect instead
		"-port",				-- Parameter Use -connect instead
		"-connect",				-- Parameter TCP/IP where to connect (default is :4433)
		"-bind",				-- Parameter bind local address for connection
		"-proxy",				-- Parameter Connect to via specified proxy to the real server
		"-unix",				-- Parameter Connect over the specified Unix-domain socket
		"-verify",				-- Parameter Turn on peer certificate verification
		"-nameopt",				-- Parameter Various certificate name options
		"-pass",				-- Parameter Private key file pass phrase source
		"-dane_tlsa_domain",	-- Parameter DANE TLSA base domain
		"-dane_tlsa_rrdata",	-- Parameter DANE TLSA rrdata presentation form
		"-starttls",			-- Parameter Use the appropriate STARTTLS command before starting TLS
		"-xmpphost",			-- Parameter Alias of -name option for "-starttls xmpp[-server]"
		"-use_srtp",			-- Parameter Offer SRTP key management with a colon-separated profile list
		"-keymatexport",		-- Parameter Export keying material using label
		"-keymatexportlen",		-- Parameter Export len bytes of keying material (default 20)
		"-name",				-- Parameter Hostname for "-starttls lmtp", "-starttls smtp" or "-starttls xmpp[-server]"
		"-servername",			-- Parameter Set TLS extension servername (SNI) in ClientHello (default)
		"-serverinfo",			-- Parameter types  Send empty ClientHello extensions (comma-separated numbers)
		"-alpn",				-- Parameter Enable ALPN extension (comma-separated list)
		"-max_send_frag",		-- Parameter Maximum Size of send frames
		"-split_send_frag",		-- Parameter Size used to split data for encrypt pipelines
		"-max_pipelines",		-- Parameter Maximum number of encrypt/decrypt pipelines to be used
		"-read_buf",			-- Parameter Default read buffer size to be used for connections
		"-sigalgs",				-- Parameter Signature algorithms to support (colon-separated list)
		"-client_sigalgs",		-- Parameter Signature algorithms to support for client cert auth (colon-separated list)
		"-groups",				-- Parameter Groups to advertise (colon-separated list)
		"-curves",				-- Parameter Groups to advertise (colon-separated list)
		"-named_curve",			-- Parameter Elliptic curve used for ECDHE (server-side only)
		"-cipher",				-- Parameter Specify TLSv1.2 and below cipher list to be used
		"-ciphersuites",		-- Parameter Specify TLSv1.3 ciphersuites to be used
		"-min_protocol",		-- Parameter Specify the minimum protocol version to be used
		"-max_protocol",		-- Parameter Specify the maximum protocol version to be used
		"-record_padding",		-- Parameter Block size to pad TLS 1.3 records to.
		"-policy",				-- Parameter adds policy to the acceptable policy set
		"-purpose",				-- Parameter certificate chain purpose
		"-verify_name",			-- Parameter verification policy name
		"-verify_depth",		-- Parameter chain depth limit
		"-auth_level",			-- Parameter chain authentication security level
		"-attime",				-- Parameter verification epoch time
		"-verify_hostname",		-- Parameter expected peer hostname
		"-verify_email",		-- Parameter expected peer email
		"-verify_ip",			-- Parameter expected peer IP address
		"-mtu",					-- Parameter Set the link layer MTU
		"-psk_identity",		-- Parameter PSK identity
		"-psk",					-- Parameter PSK in hex (without 0x)
		"-srpuser",				-- Parameter SRP authentication for 'user'
		"-srppass",				-- Parameter Password for 'user'
		"-srp_strength",		-- Parameter Minimal length in bits for N
		"-nextprotoneg",		-- Parameter Enable NPN extension (comma-separated list)
		"-engine",				-- Parameter Use engine, possibly a hardware device
		"-ssl_client_engine",	-- Parameter Specify engine to be used for client certificate operations
		"-certform" .. parser({"PEM", "DER"}),
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-CRLform" .. parser({"PEM", "DER"}),
		"-xcertform" .. parser({"PEM", "DER"}),
		"-xkeyform" .. parser({"PEM", "DER"}),
		"-maxfraglen" .. parser({"512", "1024", "2048", "4096"}),
		"-cert" .. parser{clink.filematches}, 			-- Parameter Certificate file to use, PEM format assumed
		"-key" .. parser{clink.filematches}, 			-- Parameter Private key file to use, if not in -cert file
		"-CAfile" .. parser{clink.filematches}, 		-- Parameter PEM format file of CA's
		"-requestCAfile" .. parser{clink.filematches}, 	-- Parameter PEM format file of CA names to send to the server
		"-rand" .. parser{clink.filematches}, 			-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches}, 		-- Parameter Write random data to the specified file
		"-sess_out" .. parser{clink.filematches}, 		-- Parameter File to write SSL session to
		"-sess_in" .. parser{clink.filematches}, 		-- Parameter File to read SSL session from
		"-CRL" .. parser{clink.filematches}, 			-- Parameter CRL file to use
		"-cert_chain" .. parser{clink.filematches}, 	-- Parameter Certificate chain file (in PEM format)
		"-chainCAfile" .. parser{clink.filematches}, 	-- Parameter CA file for certificate chain (PEM format)
		"-verifyCAfile" .. parser{clink.filematches}, 	-- Parameter CA file for certificate verification (PEM format)
		"-ssl_config" .. parser{clink.filematches}, 	-- Parameter Use specified configuration file
		"-xkey" .. parser{clink.filematches}, 			-- Parameter key for Extended certificates
		"-xcert" .. parser{clink.filematches}, 			-- Parameter cert for Extended certificates
		"-xchain" .. parser{clink.filematches}, 		-- Parameter chain for Extended certificates
		"-psk_session" .. parser{clink.filematches},	-- Parameter File to read PSK SSL session from
		"-ctlogfile" .. parser{clink.filematches}, 		-- Parameter CT log list CONF file
		"-keylogfile" .. parser{clink.filematches}, 	-- Parameter Write TLS secrets to file
		"-early_data" .. parser{clink.filematches}, 	-- Parameter File to send as early data
		"-CApath" .. parser{clink.filematches}, 		-- Parameter PEM format directory of CA's
		"-chainCApath" .. parser{clink.filematches}, 	-- Parameter Use dir as cert store path to build CA certificate chain
		"-verifyCApath" .. parser{clink.filematches} 	-- Parameter Use dir as cert store path to verify CA certificate
	),
	"s_server" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-4", "-6", "-unlink", "-nbio_test", "-crlf", "-debug", "-msg",
		"-state", "-no-CAfile", "-no-CApath", "-nocert", "-quiet",
		"-no_resume_ephemeral", "-www", "-WWW", "-servername_fatal", "-tlsextdebug",
		"-HTTP", "-crl_download", "-no_cache", "-ext_cache", "-verify_return_error",
		"-verify_quiet", "-build_chain", "-ign_eof", "-no_ign_eof", "-status",
		"-status_verbose", "-security_debug", "-security_debug_verbose", "-brief",
		"-rev", "-async", "-no_ssl3", "-no_tls1", "-no_tls1_1", "-no_tls1_2",
		"-no_tls1_3", "-bugs", "-no_comp", "-comp", "-no_ticket", "-serverpref",
		"-legacy_renegotiation", "-no_renegotiation", "-legacy_server_connect",
		"-no_resumption_on_reneg", "-no_legacy_server_connect", "-allow_no_dhe_kex",
		"-prioritize_chacha", "-strict", "-debug_broken_protocol", "-no_middlebox",
		"-ignore_critical", "-issuer_checks", "-crl_check", "-crl_check_all",
		"-policy_check", "-explicit_policy", "-inhibit_any", "-inhibit_map",
		"-x509_strict", "-extended_crl", "-use_deltas", "-policy_print",
		"-check_ss_sig", "-trusted_first", "-suiteB_128_only", "-suiteB_128",
		"-suiteB_192", "-partial_chain", "-no_alt_chains", "-no_check_time",
		"-allow_proxy_certs", "-xchain_build", "-nbio", "-tls1", "-tls1_1",
		"-tls1_2", "-tls1_3", "-dtls", "-timeout", "-listen", "-stateless",
		"-dtls1", "-dtls1_2", "-no_dhe", "-early_data", "-anti_replay",
		"-no_anti_replay",
		"-port",				-- Parameter TCP/IP port to listen on for connections (default is 4433)
		"-accept",				-- Parameter TCP/IP optional host:port to listen on (default is *:4433)
		"-unix",				-- Parameter Unix domain socket to accept on
		"-context",				-- Parameter Set session ID context
		"-verify",				-- Parameter Turn on peer certificate verification
		"-Verify",				-- Parameter Turn on peer certificate verification, must have a cert
		"-nameopt",				-- Parameter Various certificate name options
		"-naccept",				-- Parameter Terminate after #num connections
		"-serverinfo",			-- Parameter PEM serverinfo file for certificate
		"-pass",				-- Parameter Private key file pass phrase source
		"-dpass",				-- Parameter Second private key file pass phrase source
		"-servername",			-- Parameter Servername for HostName TLS extension
		"-id_prefix",			-- Parameter Generate SSL/TLS session IDs prefixed by arg
		"-keymatexport",		-- Parameter Export keying material using label
		"-keymatexportlen",		-- Parameter Export len bytes of keying material (default 20)
		"-status_timeout",		-- Parameter Status request responder timeout
		"-status_url",			-- Parameter Status request fallback URL
		"-ssl_config",			-- Parameter Configure SSL_CTX using the configuration 'val'
		"-max_send_frag",		-- Parameter Maximum Size of send frames
		"-split_send_frag",		-- Parameter Size used to split data for encrypt pipelines
		"-max_pipelines",		-- Parameter Maximum number of encrypt/decrypt pipelines to be used
		"-read_buf",			-- Parameter Default read buffer size to be used for connections
		"-sigalgs",				-- Parameter Signature algorithms (colon-separated list)
		"-client_sigalgs",		-- Parameter Signature algorithms for client cert auth (colon-separated list)
		"-groups",				-- Parameter Groups to advertise (colon-separated list)
		"-curves",				-- Parameter Groups to advertise (colon-separated list)
		"-named_curve",			-- Parameter Elliptic curve used for ECDHE (server-side only)
		"-cipher",				-- Parameter Specify TLSv1.2 and below cipher list to be used
		"-ciphersuites",		-- Parameter Specify TLSv1.3 ciphersuites to be used
		"-min_protocol",		-- Parameter Specify the minimum protocol version to be used
		"-max_protocol",		-- Parameter Specify the maximum protocol version to be used
		"-record_padding",		-- Parameter Block size to pad TLS 1.3 records to.
		"-policy",				-- Parameter adds policy to the acceptable policy set
		"-purpose",				-- Parameter certificate chain purpose
		"-verify_name",			-- Parameter verification policy name
		"-verify_depth",		-- Parameter chain depth limit
		"-auth_level",			-- Parameter chain authentication security level
		"-attime",				-- Parameter verification epoch time
		"-verify_hostname",		-- Parameter expected peer hostname
		"-verify_email",		-- Parameter expected peer email
		"-verify_ip",			-- Parameter expected peer IP address
		"-psk_identity",		-- Parameter PSK identity to expect
		"-psk_hint",			-- Parameter PSK identity hint to use
		"-psk",					-- Parameter PSK in hex (without 0x)
		"-srpuserseed",			-- Parameter A seed string for a default user salt
		"-mtu",					-- Parameter Set link layer MTU
		"-nextprotoneg",		-- Parameter Set the protocols for the NPN extension (comma-separated list)
		"-use_srtp",			-- Parameter Offer SRTP key management with a colon-separated profile list
		"-alpn",				-- Parameter Set the protocols for the ALPN extension (comma-separated list)
		"-engine",				-- Parameter Use engine, possibly a hardware device
		"-max_early_data",		-- Parameter The maximum number of bytes of early data as advertised in tickets
		"-recv_max_early_data",	-- Parameter The maximum number of bytes of early data (hard limit)
		"-num_tickets",			-- Parameter The number of TLSv1.3 session tickets
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-certform" .. parser({"PEM", "DER"}),
		"-dcertform" .. parser({"PEM", "DER"}),
		"-dkeyform" .. parser({"PEM", "DER"}),
		"-CRLform" .. parser({"PEM", "DER"}),
		"-xcertform" .. parser({"PEM", "DER"}),
		"-xkeyform" .. parser({"PEM", "DER"}),
		"-cert" .. parser{clink.filematches}, 			-- Parameter Cert to use; default is server.pem
		"-key" .. parser{clink.filematches}, 			-- Parameter Private Key if not in -cert;
		"-dcert" .. parser{clink.filematches}, 			-- Parameter Second certificate file to use
		"-dhparam" .. parser{clink.filematches}, 		-- Parameter DH parameters file to use
		"-dkey" .. parser{clink.filematches}, 			-- Parameter Second private key file to use
		"-msgfile" .. parser{clink.filematches}, 		-- Parameter File to send output of -msg or -trace
		"-CAfile" .. parser{clink.filematches}, 		-- Parameter PEM format file of CA's
		"-cert2" .. parser{clink.filematches}, 			-- Parameter Cert to use for srvname; def isserver2.pem
		"-key2" .. parser{clink.filematches}, 			-- Parameter -Private Key to use if not in -cert2
		"-rand" .. parser{clink.filematches}, 			-- Parameter Load the file(s) into the rnd generator
		"-writerand" .. parser{clink.filematches}, 		-- Parameter Write random data to the specified file
		"-CRL" .. parser{clink.filematches}, 			-- Parameter CRL file to use
		"-cert_chain" .. parser{clink.filematches}, 	-- Parameter certificate chain file in PEM format
		"-dcert_chain" .. parser{clink.filematches},	-- Parameter second cert chain file in PEM format
		"-chainCAfile" .. parser{clink.filematches},	-- Parameter CA file for cert chain (PEM format)
		"-verifyCAfile" .. parser{clink.filematches}, 	-- Parameter CA file for cert verification (PEM format)
		"-status_file" .. parser{clink.filematches}, 	-- Parameter File containing DER encoded OCSP Response
		"-xkey" .. parser{clink.filematches}, 			-- Parameter key for Extended certificates
		"-xcert" .. parser{clink.filematches}, 			-- Parameter cert for Extended certificates
		"-xchain" .. parser{clink.filematches}, 		-- Parameter chain for Extended certificates
		"-psk_session" .. parser{clink.filematches}, 	-- Parameter File to read PSK SSL session from
		"-srpvfile" .. parser{clink.filematches}, 		-- Parameter The verifier file for SRP
		"-keylogfile" .. parser{clink.filematches}, 	-- Parameter Write TLS secrets to file
		"-CApath" .. parser{clink.dirmatches}, 			-- Parameter PEM format directory of CA's
		"-chainCApath" .. parser{clink.dirmatches}, 	-- Parameter use path to build CA certificate chain
		"-verifyCApath" .. parser{clink.dirmatches} 	-- Parameter use dir as path to verify CA certificate
	),
	"s_time" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-no-CAfile", "-no-CApath", "-new", "-reuse", "-bugs",
		"-connect",			-- Parameter Where to connect as post:port (default is localhost:4433)
		"-cipher",			-- Parameter TLSv1.2 and below cipher list to be used
		"-ciphersuites",	-- Parameter Specify TLSv1.3 ciphersuites to be used
		"-nameopt",			-- Parameter Various certificate name options
		"-verify",			-- Parameter Turn on peer certificate verification, set depth
		"-time",			-- Parameter Seconds to collect data, default 30
		"-www",				-- Parameter Fetch specified page from the site
		"-cert" .. parser{clink.filematches}, 		-- Parameter Cert file to use, PEM format assumed
		"-key" .. parser{clink.filematches}, 		-- Parameter File with key, PEM; default is -cert file
		"-cafile" .. parser{clink.filematches}, 	-- Parameter PEM format file of CA's
		"-CAfile" .. parser{clink.filematches}, 	-- Parameter PEM format file of CA's
		"-CApath" .. parser{clink.dirmatches} 	-- Parameter PEM format directory of CA's
	),
	"sess_id" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-text", "-cert", "-noout",
		"-context",	-- Parameter Set the session ID context
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER", "NSS"}),
		"-in" .. parser{clink.filematches}, 	-- Parameter Input file - default stdin
		"-out" .. parser{clink.filematches} 	-- Parameter Output file - default stdout
	),
	"smime" .. parser(
		parser({clink.filematches}),
		"-help", "-encrypt", "-decrypt", "-sign", "-verify", "-pk7out",
		"-nointern", "-nosigs", "-noverify", "-nocerts", "-nodetach",
		"-noattr", "-binary", "-text", "-no-CAfile", "-no-CApath", "-resign",
		"-nochain", "-nosmimecap", "-stream", "-indef", "-noindef", "-crlfeol",
		"-*", "-ignore_critical", "-issuer_checks", "-crl_check", "-crl_check_all",
		"-policy_check", "-explicit_policy", "-inhibit_any", "-inhibit_map",
		"-x509_strict", "-extended_crl", "-use_deltas", "-policy_print",
		"-check_ss_sig", "-trusted_first", "-suiteB_128_only", "-suiteB_128",
		"-suiteB_192", "-partial_chain", "-no_alt_chains", "-no_check_time",
		"-allow_proxy_certs",
		"-to",				-- Parameter To address
		"-from",			-- Parameter From address
		"-subject",			-- Parameter Subject
		"-passin",			-- Parameter Input file pass phrase source
		"-md",				-- Parameter Digest algorithm to use when signing or resigning
		"-policy",			-- Parameter adds policy to the acceptable policy set
		"-purpose",			-- Parameter certificate chain purpose
		"-verify_name",		-- Parameter verification policy name
		"-verify_depth",	-- Parameter chain depth limit
		"-auth_level",		-- Parameter chain authentication security level
		"-attime",			-- Parameter verification epoch time
		"-verify_hostname",	-- Parameter expected peer hostname
		"-verify_email",	-- Parameter expected peer email
		"-verify_ip",		-- Parameter expected peer IP address
		"-engine",			-- Parameter Use engine, possibly a hardware device
		"-inform" .. parser({"SMIME", "PEM", "DER"}),
		"-keyform" .. parser({"PEM", "ENGINE"}),
		"-outform" .. parser({"SMIME", "PEM", "DER"}),
		"-certfile" .. parser{clink.filematches}, 	-- Parameter Other certificates file
		"-signer" .. parser{clink.filematches}, 	-- Parameter Signer certificate file
		"-recip" .. parser{clink.filematches}, 		-- Parameter Recipient certificate file for decryption
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file
		"-inkey" .. parser{clink.filematches}, 		-- Parameter Input private key (if not signer or recipient)
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file
		"-content" .. parser{clink.filematches}, 	-- Parameter Supply or override content for detached signature
		"-CAfile" .. parser{clink.filematches}, 	-- Parameter Trusted certificates file
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches}, 	-- Parameter Write random data to the specified file
		"-CApath" .. parser{clink.dirmatches}	 	-- Parameter Trusted certificates directory
	),
	"speed" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-decrypt", "-aead", "-mb", "-mr", "-elapsed",
		"-evp",			-- Parameter Use EVP-named cipher or digest
		"-async_jobs",	-- Parameter Enable async mode and start specified number of jobs
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-primes",		-- Parameter Specify number of primes (for RSA only)
		"-seconds",		-- Parameter Run benchmarks for specified amount of seconds
		"-bytes",		-- Parameter Run [non-PKI] benchmarks on custom-sized buffer
		"-misalign",	-- Parameter Use specified offset to mis-align buffers
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches} 	-- Parameter Write random data to the specified file
	),
	"spkac" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-noout", "-pubkey", "-verify",
		"-passin",		-- Parameter Input file pass phrase source
		"-challenge",	-- Parameter Challenge string
		"-spkac",		-- Parameter Alternative SPKAC name
		"-spksect",		-- Parameter Specify the name of an SPKAC-dedicated section of configuration
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-in" .. parser{clink.filematches},		-- Parameter Input file
		"-out" .. parser{clink.filematches},	-- Parameter Output file
		"-key" .. parser{clink.filematches} 	-- Parameter Create SPKAC using private key
	),
	"srp" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-verbose", "-add", "-modify", "-delete", "-list",
		"-name",		-- Parameter The particular srp definition to use
		"-gn",			-- Parameter Set g and N values to be used for new verifier
		"-userinfo",	-- Parameter Additional info to be set for user
		"-passin",		-- Parameter Input file pass phrase source
		"-passout",		-- Parameter Output file pass phrase source
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-config" .. parser{clink.filematches}, 	-- Parameter A config file
		"-srpvfile" .. parser{clink.filematches}, 	-- Parameter The srp verifier file name
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser{clink.filematches} 	-- Parameter Write random data to the specified file
	),
	"storeutl" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-text", "-noout", "-certs", "-keys", "-crls", "-*", "-r",
		"-passin",		-- Parameter Input file pass phrase source
		"-subject",		-- Parameter Search by subject
		"-issuer",		-- Parameter Search by issuer and serial, issuer name
		"-serial",		-- Parameter Search by issuer and serial, serial number
		"-fingerprint",	-- Parameter Search by public key fingerprint, given in hex
		"-alias",		-- Parameter Search by alias
		"-engine",		-- Parameter Use engine, possibly a hardware device
 		"-out" .. parser{clink.filematches} 	-- Parameter Output file - default stdout
	),
	"ts" .. parser({}, -- empty {}: don't suggest any positional args
		"-help",
		"-query" .. parser({
			"-no_nonce", "-cert", "-token_in", "-token_out", "-text", "-*",
			"-section",		-- Parameter Section to use within config file
			"-digest",		-- Parameter Digest (as a hex string)
			"-tspolicy",	-- Parameter Policy OID to use
			"-passin",		-- Parameter Input file pass phrase source
			"-engine",		-- Parameter Use engine, possibly a hardware device
			"-config" .. parser{clink.filematches}, 	-- Parameter Configuration file
			"-data" .. parser{clink.filematches}, 		-- Parameter File to hash
			"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
			"-writerand" .. parser{clink.filematches}, 	-- Parameter Write random data to the specified file
			"-in" .. parser{clink.filematches}, 		-- Parameter Input file
			"-out" .. parser{clink.filematches}, 		-- Parameter Output file
			"-queryfile" .. parser{clink.filematches}, 	-- Parameter File containing a TS query
			"-inkey" .. parser{clink.filematches}, 		-- Parameter File with private key for reply
			"-signer" .. parser{clink.filematches}, 	-- Parameter Signer certificate file
			"-chain" .. parser{clink.filematches}, 		-- Parameter File with signer CA chain
			"-CAfile" .. parser{clink.filematches}, 	-- Parameter File with trusted CA certs
			"-untrusted" .. parser{clink.filematches}, 	-- Parameter File with untrusted certs
			"-CApath" .. parser{clink.dirmatches}, 	-- Parameter Path to trusted CA files
		}),
		"-reply" .. parser({
			"-no_nonce", "-cert", "-token_in", "-token_out", "-text", "-*",
			"-section",		-- Parameter Section to use within config file
			"-digest",		-- Parameter Digest (as a hex string)
			"-tspolicy",	-- Parameter Policy OID to use
			"-passin",		-- Parameter Input file pass phrase source
			"-engine",		-- Parameter Use engine, possibly a hardware device
			"-config" .. parser{clink.filematches}, 	-- Parameter Configuration file
			"-data" .. parser{clink.filematches}, 		-- Parameter File to hash
			"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
			"-writerand" .. parser{clink.filematches}, 	-- Parameter Write random data to the specified file
			"-in" .. parser{clink.filematches}, 		-- Parameter Input file
			"-out" .. parser{clink.filematches}, 		-- Parameter Output file
			"-queryfile" .. parser{clink.filematches}, 	-- Parameter File containing a TS query
			"-inkey" .. parser{clink.filematches}, 		-- Parameter File with private key for reply
			"-signer" .. parser{clink.filematches}, 	-- Parameter Signer certificate file
			"-chain" .. parser{clink.filematches}, 		-- Parameter File with signer CA chain
			"-CAfile" .. parser{clink.filematches}, 	-- Parameter File with trusted CA certs
			"-untrusted" .. parser{clink.filematches}, 	-- Parameter File with untrusted certs
			"-CApath" .. parser{clink.dirmatches}, 	-- Parameter Path to trusted CA files
		}),
		"-verify" .. parser({
			-- common part (like -query  and -reply)
			"-no_nonce", "-cert", "-token_in", "-token_out", "-text", "-*",
			"-section",		-- Parameter Section to use within config file
			"-digest",		-- Parameter Digest (as a hex string)
			"-tspolicy",	-- Parameter Policy OID to use
			"-passin",		-- Parameter Input file pass phrase source
			"-engine",		-- Parameter Use engine, possibly a hardware device
			"-config" .. parser{clink.filematches}, 	-- Parameter Configuration file
			"-data" .. parser{clink.filematches}, 		-- Parameter File to hash
			"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into the random number generator
			"-writerand" .. parser{clink.filematches}, 	-- Parameter Write random data to the specified file
			"-in" .. parser{clink.filematches}, 		-- Parameter Input file
			"-out" .. parser{clink.filematches}, 		-- Parameter Output file
			"-queryfile" .. parser{clink.filematches}, 	-- Parameter File containing a TS query
			"-inkey" .. parser{clink.filematches}, 		-- Parameter File with private key for reply
			"-signer" .. parser{clink.filematches}, 	-- Parameter Signer certificate file
			"-chain" .. parser{clink.filematches}, 		-- Parameter File with signer CA chain
			"-CAfile" .. parser{clink.filematches}, 	-- Parameter File with trusted CA certs
			"-untrusted" .. parser{clink.filematches}, 	-- Parameter File with untrusted certs
			"-CApath" .. parser{clink.dirmatches}, 	-- Parameter Path to trusted CA files
			-- special to -verify parameter
			"-ignore_critical", "-issuer_checks", "-crl_check",
			"-crl_check_all", "-policy_check", "-explicit_policy",
			"-inhibit_any", "-inhibit_map", "-x509_strict", "-extended_crl",
			"-use_deltas", "-policy_print", "-check_ss_sig", "-trusted_first",
			"-suiteB_128_only", "-suiteB_128", "-suiteB_192", "-partial_chain",
			"-no_alt_chains", "-no_check_time", "-allow_proxy_certs",
			"-policy",			-- Parameter adds policy to the acceptable policy set
			"-purpose",			-- Parameter certificate chain purpose
			"-verify_name",		-- Parameter verification policy name
			"-verify_depth",	-- Parameter chain depth limit
			"-auth_level",		-- Parameter chain authentication security level
			"-attime",			-- Parameter verification epoch time
			"-verify_hostname",	-- Parameter expected peer hostname
			"-verify_email",	-- Parameter expected peer email
			"-verify_ip"		-- Parameter expected peer IP address
		})
	),
	"verify"  .. parser(
		parser({clink.filematches}),
		"-help", "-verbose", "-no-CAfile", "-no-CApath", "-crl_download",
		"-show_chain", "-ignore_critical", "-issuer_checks", "-crl_check",
		"-crl_check_all", "-policy_check", "-explicit_policy", "-inhibit_any",  
		"-inhibit_map", "-x509_strict", "-extended_crl", "-use_deltas", 
		"-policy_print", "-check_ss_sig", "-trusted_first", "-suiteB_128_only",
		"-suiteB_128", "-suiteB_192", "-partial_chain", "-no_alt_chains", 
		"-no_check_time", "-allow_proxy_certs", 
		"-nameopt",			-- Parameter Various certificate name options
		"-policy",			-- Parameter adds policy to the acceptable policy set
		"-verify_depth",	-- Parameter chain depth limit
		"-auth_level",		-- Parameter chain authentication security level
		"-attime",			-- Parameter verification epoch time
		"-verify_hostname",	-- Parameter expected peer hostname
		"-verify_email",	-- Parameter expected peer email
		"-verify_ip",		-- Parameter expected peer IP address
		"-engine",			-- Parameter Use engine, possibly a hardware device
		"-purpose" .. parser({
			"sslclient", "sslserver", "nssslserver", "smimesign", 
			"smimeencrypt", "crlsign", "any", "ocsphelper", 
			"timestampsign" 
		}),
		"-verify_name" .. parser({ "default", "pkcs7", "smime_sign", "ssl_client", "ssl_server" }),
		"-CAfile" .. parser{clink.filematches}, 	-- Parameter A file of trusted certificates
		"-CApath" .. parser{clink.filematches}, 	-- Parameter A directory of trusted certificates
		"-untrusted" .. parser{clink.filematches}, 	-- Parameter A file of untrusted certificates
		"-trusted" .. parser{clink.filematches}, 	-- Parameter A file of trusted certificates
		"-CRLfile" .. parser{clink.filematches} 	-- Parameter File containing one or more CRL's (in PEM format) to load
	),
	"version" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-a", "-b", "-d", "-e", "-f", "-o", "-p", "-r", "-v"
	),
	"x509" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-serial", "-subject_hash", "-issuer_hash", "-hash",
		"-subject", "-issuer", "-email", "-startdate", "-enddate",
		"-purpose", "-dates", "-modulus", "-pubkey", "-fingerprint",
		"-alias", "-noout", "-nocert", "-ocspid", "-ocsp_uri", "-trustout",
		"-clrtrust", "-clrext", "-x509toreq", "-req", "-CAcreateserial",
		"-text", "-C", "-next_serial", "-clrreject", "-badsig", "-*",
		"-subject_hash_old", "-issuer_hash_old", "-preserve_dates",
		"-passin",		-- Parameter Private key password/pass-phrase source
		"-addtrust",	-- Parameter Trust certificate for a given purpose
		"-addreject",	-- Parameter Reject certificate for a given purpose
		"-setalias",	-- Parameter Set certificate alias
		"-days",		-- Parameter How long till expiry of a signed certificate - def 30 days
		"-checkend",	-- Parameter Check whether the cert expires in the next n seconds, exit code 1 or 0
		"-signkey",		-- Parameter Self sign cert with arg
		"-set_serial",	-- Parameter Serial number to use
		"-ext",			-- Parameter Print various X509V3 extensions
		"-extensions",	-- Parameter Section from config file to use
		"-nameopt",		-- Parameter Various certificate name options
		"-certopt",		-- Parameter Various certificate text options
		"-checkhost",	-- Parameter Check certificate matches host
		"-checkemail",	-- Parameter Check certificate matches email
		"-checkip",		-- Parameter Check certificate matches ipaddr
		"-sigopt",		-- Parameter Signature parameter in n:v form
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER"}),
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-CAform" .. parser({"PEM", "DER"}),
		"-CAkeyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-in" .. parser{clink.filematches}, 		-- Parameter Input file - default stdin
		"-out" .. parser{clink.filematches}, 		-- Parameter Output file - default stdout
		"-CA" .. parser{clink.filematches}, 		-- Parameter Set the CA certificate, must be PEM format
		"-CAkey" .. parser{clink.filematches}, 		-- Parameter The CA key as PEM; if not in CAfile
		"-CAserial" .. parser{clink.filematches}, 	-- Parameter Serial file
		"-extfile" .. parser{clink.filematches}, 	-- Parameter File with X509V3 extensions to add
		"-rand" .. parser{clink.filematches}, 		-- Parameter Load the file(s) into random number generator
		"-writerand" .. parser{clink.filematches}, 	-- Parameter Write random data to the specified file
		"-force_pubkey" .. parser{clink.filematches} -- Parameter Force the Key to put inside certificate
	)
})

clink.arg.register_parser("openssl", openssl_parser)

