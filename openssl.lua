--[[

What is this?
This is a definition file for command completion in Clink.

Are there any requirements?
- "modern CLink" (version 1.2 or later)
- OpenSSL 1.1.*, 3.0.*, 3.1.* - 3.4.* or 3.5

How to use this file?
- Run 'clink info'
- Place the file in one of the script locations
- Restart clink
- Now you should have tab completion for openssl parameters

Where do I get the latest version?
https://github.com/dodmi/Clink-Addons/tree/master/

When was this file updated?
2025-04-21

]]--

-- read the file "filename" into a table
local function readFile(filename)
    local lines = {}
    local f = io.open(filename, "r")
    if not f then return lines end

    for line in f:lines() do table.insert(lines, line) end

    f:close()
    return lines
end

-- return the installed OpenSSL Version (Major.Minor)
local function getOpenSSLVersion()
    local tmpFileName = os.tmpname()
    os.execute('openssl version > ' .. tmpFileName)
    local fileContent = readFile(tmpFileName)
    os.remove(tmpFileName)
	local version = "0.0"
	local tmp
    for _, line in ipairs(fileContent) do
        tmp = line:match('^OpenSSL%s+(%d+%.%d+)%..*$')
		if tmp then
			version = tmp
			break
		end
    end
    return version
end

local parser = clink.arg.new_parser

local digests = {
	"BLAKE2B512", "BLAKE2S256", "MD5", "RMD160", "SHA1", "SHA224",
	"SHA256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHA384",
	"SHA512", "SHA512-224", "SHA512-256", "SHAKE128", "SHAKE256", "SM3"
}

if getOpenSSLVersion() == "1.1" then
	digests = {
		"BLAKE2B512", "BLAKE2S256", "MD4", "MD5", "MD5-SHA1", "MDC2",
		"RIPEMD160", "RSA-SHA1", "SHA1", "SHA224", "SHA256", "SHA3-224",
		"SHA3-256", "SHA3-384", "SHA3-512", "SHA384", "SHA512",
		"SHA512-224", "SHA512-256", "SHAKE128", "SHAKE256", "SM3", "WHIRLPOOL"
	}
end

local ciphers = {
	"AES-128-CBC", "AES-128-ECB", "AES-192-CBC", "AES-192-ECB", "AES-256-CBC",
	"AES-256-ECB", "ARIA-128-CBC", "ARIA-128-CFB", "ARIA-128-CFB1",
	"ARIA-128-CFB8", "ARIA-128-CTR", "ARIA-128-ECB", "ARIA-128-OFB",
	"ARIA-192-CBC", "ARIA-192-CFB", "ARIA-192-CFB1", "ARIA-192-CFB8",
	"ARIA-192-CTR", "ARIA-192-ECB", "ARIA-192-OFB", "ARIA-256-CBC",
	"ARIA-256-CFB", "ARIA-256-CFB1", "ARIA-256-CFB8", "ARIA-256-CTR",
	"ARIA-256-ECB", "ARIA-256-OFB", "CAMELLIA-128-CBC", "CAMELLIA-128-ECB",
	"CAMELLIA-192-CBC", "CAMELLIA-192-ECB", "CAMELLIA-256-CBC", "CAMELLIA-256-ECB",
	"DES-EDE", "DES-EDE-CBC", "DES-EDE-CFB", "DES-EDE-OFB", "DES-EDE3", "DES-EDE3-CBC",
	"DES-EDE3-CFB", "DES-EDE3-OFB", "DES3", "SM4-CBC", "SM4-CFB", "SM4-CTR", "SM4-ECB",
	"SM4-OFB"
}

if getOpenSSLVersion() == "1.1" then
	ciphers = {
		"AES-128-CBC", "AES-128-ECB", "AES-192-CBC", "AES-192-ECB", "AES-256-CBC",
		"AES-256-ECB", "ARIA-128-CBC", "ARIA-128-CFB", "ARIA-128-CFB1", "ARIA-128-CFB8",
		"ARIA-128-CTR", "ARIA-128-ECB", "ARIA-128-OFB", "ARIA-192-CBC", "ARIA-192-CFB",
		"ARIA-192-CFB1", "ARIA-192-CFB8", "ARIA-192-CTR", "ARIA-192-ECB", "ARIA-192-OFB",
		"ARIA-256-CBC", "ARIA-256-CFB", "ARIA-256-CFB1", "ARIA-256-CFB8", "ARIA-256-CTR",
		"ARIA-256-ECB", "ARIA-256-OFB", "BASE64", "BF", "BF-CBC", "BF-CFB", "BF-ECB",
		"BF-OFB", "CAMELLIA-128-CBC", "CAMELLIA-128-ECB", "CAMELLIA-192-CBC",
		"CAMELLIA-192-ECB", "CAMELLIA-256-CBC", "CAMELLIA-256-ECB", "CAST", "CAST-CBC",
		"CAST5-CBC", "CAST5-CFB", "CAST5-ECB", "CAST5-OFB", "DES", "DES-CBC", "DES-CFB",
		"DES-ECB", "DES-EDE", "DES-EDE-CBC", "DES-EDE-CFB", "DES-EDE-OFB", "DES-EDE3",
		"DES-EDE3-CBC", "DES-EDE3-CFB", "DES-EDE3-OFB", "DES-OFB", "DES3", "DESX", "RC2",
		"RC2-40-CBC", "RC2-64-CBC", "RC2-CBC", "RC2-CFB", "RC2-ECB", "RC2-OFB", "RC4",
		"RC4-40", "SEED", "SEED-CBC", "SEED-CFB", "SEED-ECB", "SEED-OFB", "SM4-CBC",
		"SM4-CFB", "SM4-CTR", "SM4-ECB", "SM4-OFB"
	}
end

local openSSL10CommandLine = {
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
 		"-md" .. parser(digests),
 		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
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
		"-md" .. parser(digests),
		"-outform" .. parser({"SMIME", "PEM", "DER"}),
		"-rctform" .. parser({"PEM", "DER"}),
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file
		"-out" .. parser({clink.filematches}), 				-- Parameter Output file
		"-verify_receipt" .. parser({clink.filematches}), 	-- Parameter infile
		"-certfile" .. parser({clink.filematches}), 			-- Parameter Other certificates file
		"-CAfile" .. parser({clink.filematches}), 				-- Parameter Trusted certificates file
		"-recip" .. parser({clink.filematches}), 				-- Parameter Recipient cert file for decryption
		"-signer" .. parser({clink.filematches}),				-- Parameter Signer certificate file
		"-certsout" .. parser({clink.filematches}), 			-- Parameter Certificate output file
		"-inkey" .. parser({clink.filematches}), 				-- Parameter Input private key (if not signer or recipient)
		"-rand" .. parser({clink.filematches}), 				-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}), 			-- Parameter Write random data to the specified file
		"-content" .. parser({clink.filematches}), 				-- Parameter Supply or override content for detached signature
		"-CApath" .. parser({clink.dirmatches}) 				-- Parameter trusted certificates directory
	),
	"crl" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-issuer", "-lastupdate", "-nextupdate", "-noout",
		"-fingerprint", "-crlnumber", "-badsig", "-no-CAfile",
		"-no-CApath", "-verify", "-text", "-hash", "-*", "-hash_old",
		"-nameopt",			-- Parameter Various certificate name options
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER"}),
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file - default stdin
		"-out" .. parser({clink.filematches}), 		-- Parameter output file - default stdout
		"-key" .. parser({clink.filematches}), 		-- Parameter CRL signing Private key to use
		"-gendelta" .. parser({clink.filematches}), 	-- Parameter Other CRL to compare/diff to the Input one
		"-CAfile" .. parser({clink.filematches}), 	-- Parameter Verify CRL using certificates in file name
		"-CApath" .. parser({clink.dirmatches})	 	-- Parameter Verify CRL using certificates in dir
	),
	"crl2pkcs7" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-nocrl",
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file
		"-certfile" .. parser({clink.filematches})	-- Parameter File of chain of certs to a trusted CA
	),
	"dgst" .. parser(
		parser({clink.filematches}),
		"-help", "-list", "-c", " -r", "-hex", "-binary", "-d",
		"-debug", "-fips-fingerprint", "-*", "-engine_impl",
		"-hmac",		-- Parameter Create hashed MAC with key
		"-mac",			-- Parameter Create MAC (not necessarily HMAC)
		"-sigopt",		-- Parameter Signature parameter in n:v form
		"-macopt",		-- Parameter MAC algorithm parameters in n:v form or key
		"-engine",		-- Parameter Use engine e, possibly a hardware device
		"-passin", 		-- Parameter Input file pass phrase source
		"-signature", 	-- Parameter File with signature to verify
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-out" .. parser({clink.filematches}), 		-- Parameter Output to filename rather than stdout
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}), 	-- Parameter Write random data to the specified file
		"-sign" .. parser({clink.filematches}), 		-- Parameter Sign digest using private key
		"-verify" .. parser({clink.filematches}), 	-- Parameter Verify a signature using public key
		"-prverify" .. parser({clink.filematches}) 	-- Parameter Verify a signature using private key
	),
	"dhparam" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-check", "-text", "-noout", "-C", "-2", "-5", "-dsaparam",
		"-engine",		-- Parameter Use engine e, possibly a hardware device
		"-inform" .. parser({"PEM", "DER"}),
 		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}) 	-- Parameter Write random data to the specified file
	),
	"dsa" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-noout", "-text", "-modulus", "-pubin", "-pubout",
		"-*", "-pvk-strong", "-pvk-weak", "-pvk-none",
		"-inform" .. parser({"PEM", "DER", "PVK"}),
		"-outform" .. parser({"PEM", "DER", "PVK"}),
		"-engine",	-- Parameter Use engine e, possibly a hardware device
		"-passout",	-- Parameter Output file pass phrase source
		"-passin", 	-- Parameter Input file pass phrase source
		"-in" .. parser({clink.filematches}), 		-- Parameter Input key
		"-out" .. parser({clink.filematches}) 		-- Parameter Output file
	),
	"dsaparam" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-text", "-C", "-noout", "-genkey",
		"-engine",		-- Parameter Use engine e, possibly a hardware device
		"-inform" .. parser({"PEM", "DER"}),
 		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}) 	-- Parameter Write random data to the specified file
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
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file
		"-out" .. parser({clink.filematches}) 		-- Parameter Output file
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
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file  - default stdin
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file - default stdout
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}) 	-- Parameter Write random data to the specified file
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
		"-iter", 	-- Parameter Specify the iteration count and force use of PBKDF2
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-md" .. parser(digests),
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file
		"-kfile" .. parser({clink.filematches}), 		-- Parameter Read passphrase from file
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}) 	-- Parameter Write random data to the specified file
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
		parser({clink.filematches}),
		"-help", "-*",
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-passout", -- Parameter Output file pass phrase source
		"-out" .. parser({clink.filematches}), 		-- Parameter Output the key to the specified file
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}) 	-- Parameter Write random data to the specified file
	),
	"genpkey" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-genparam", "-text", "-*",
		"-algorithm",	-- Parameter The public key algorithm
		"-pkeyopt",		-- Parameter Set the public key algorithm option as opt:value
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-pass", 		-- Parameter Output file pass phrase source
		"-outform" .. parser({"PEM", "DER"}),
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file
		"-paramfile" .. parser({clink.filematches}) 	-- Parameter Parameters file
	),
	"genrsa" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-3", "-F4", "-f4", "-*",
		"-passout",	-- Parameter Output file pass phrase source
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-primes",	-- Parameter Specify number of primes
 		"-out" .. parser({clink.filematches}), 		-- Parameter Output the key to specified file
 		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
 		"-writerand" .. parser({clink.filematches}) 	-- Parameter Write random data to the specified file
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
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file
		"-out" .. parser({clink.filematches}) 		-- Parameter Output file
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
		"-out" .. parser({clink.filematches}), 			-- Parameter Output filename
		"-reqin" .. parser({clink.filematches}), 			-- Parameter File with the DER-encoded request
		"-respin" .. parser({clink.filematches}), 		-- Parameter File with the DER-encoded response
		"-signer" .. parser({clink.filematches}), 		-- Parameter Certificate to sign OCSP request with
		"-VAfile" .. parser({clink.filematches}), 		-- Parameter Validator certificates file
		"-sign_other" .. parser({clink.filematches}), 	-- Parameter Additional certificates to include in signed request
		"-verify_other" .. parser({clink.filematches}),	-- Parameter Additional certificates to search for signer
		"-CAfile" .. parser({clink.filematches}), 		-- Parameter Trusted certificates file
		"-signkey" .. parser({clink.filematches}), 		-- Parameter Private key to sign OCSP request with
		"-reqout" .. parser({clink.filematches}), 		-- Parameter Output file for the DER-encoded request
		"-respout" .. parser({clink.filematches}), 		-- Parameter Output file for the DER-encoded response
		"-issuer" .. parser({clink.filematches}), 		-- Parameter Issuer certificate
		"-cert" .. parser({clink.filematches}), 			-- Parameter Certificate to check
		"-index" .. parser({clink.filematches}), 			-- Parameter Certificate status index file
		"-CA" .. parser({clink.filematches}), 			-- Parameter CA certificate
		"-rsigner" .. parser({clink.filematches}), 		-- Parameter Responder certificate to sign responses with
		"-rkey" .. parser({clink.filematches}), 			-- Parameter Responder key to sign responses with
		"-rother" .. parser({clink.filematches}), 			-- Parameter Other certificates to include in response
		"-CApath" .. parser({clink.dirmatches}) 		-- Parameter Trusted certificates directory
	),
	"passwd" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-noverify", "-quiet", "-table", "-reverse", "-stdin", "-6", "-5", "-apr1", "-1", "-aixmd5", "-crypt",
		"-salt",	-- Parameter Use provided salt
		"-in" .. parser({clink.filematches}), 			-- Parameter Read passwords from file
		"-rand" .. parser({clink.filematches}), 			-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}) 		-- Parameter Write random data to the specified file
	),
	"pkcs12" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-nokeys", "-keyex", "-keysig", "-nocerts", "-clcerts",
		"-cacerts", "-noout", "-info", "-chain", "-twopass", "-nomacver", "-descert", "-export", "-noiter",  "-maciter", "-nomaciter", "-nomac", "-LMK", "-nodes", "-no-CAfile", "-no-CApath", "-*",
		"-certpbe",	-- Parameter Certificate PBE algorithm (default RC2-40)
		"-macalg",	-- Parameter Digest algorithm used in MAC (default SHA1)
		"-keypbe",	-- Parameter Private key PBE algorithm (default 3DES)
		"-name",	-- Parameter Use name as friendly name
		"-CSP",		-- Parameter Microsoft CSP name
		"-caname",	-- Parameter Use name as CA friendly name (can be repeated)
		"-passin",	-- Parameter Input file pass phrase source
		"-passout",	-- Parameter Output file pass phrase source
		"-password",-- Parameter Set import/export password source
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-inkey" .. parser({clink.filematches}),	-- Parameter Private key if not infile
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into random number generator
		"-writerand" .. parser({clink.filematches}), 	-- Parameter Write random data to the specified file
		"-certfile" .. parser({clink.filematches}), 	-- Parameter Load certs from file
		"-in" .. parser({clink.filematches}), 		-- Parameter Input filename
		"-out" .. parser({clink.filematches}), 		-- Parameter Output filename
		"-CAfile" .. parser({clink.filematches}), 	-- Parameter PEM-format file of CA's
		"-CApath" .. parser({clink.dirmatches}) 		-- Parameter PEM-format directory of CA's
	),
	"pkcs7" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-noout", "-text", "-print", "-print_certs",
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser({clink.filematches}), 	-- Parameter Input file
		"-out" .. parser({clink.filematches}) 	-- Parameter Output file
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
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}) 	-- Parameter Write random data to the specified file
	),
	"pkey" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-pubin", "-pubout", "-text_pub", "-text", "-noout", "-*", "-traditional", "-check", "-pubcheck",
		"-passin",	-- Parameter Input file pass phrase source
		"-passout",	-- Parameter Output file pass phrase source
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER"}),
		"-in" .. parser({clink.filematches}), 		-- Parameter Input key
		"-out" .. parser({clink.filematches}) 		-- Parameter Output file
	),
	"pkeyparam" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-text", "-noout", "-check",
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file
		"-out" .. parser({clink.filematches}) 		-- Parameter Output file
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
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file - default stdin
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file - default stdout
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}), 	-- Parameter Write random data to the specified file
		"-sigfile" .. parser({clink.filematches}), 	-- Parameter Signature file (verify operation only)
		"-inkey" .. parser({clink.filematches}), 		-- Parameter Input private key file
		"-peerkey" .. parser({clink.filematches}) 	-- Parameter Peer key file used in key derivation
	),
	"prime" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-hex", "-generate", "-safe",
		"-bits",	-- Parameter Size of number in bits
		"-checks"	-- Parameter Number of checks
	),
	"rand" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-base64", "-hex",
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}) 	-- Parameter Write random data to the specified file
	),
	"rehash" .. parser({}, -- empty {}: don't suggest any positional args
		"-help"
	),
	"req" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-pubkey", "-new", "-batch", "-newhdr", "-modulus",
		"-verify", "-nodes", "-noout", "-verbose", "-utf8", "-text",
		"-x509", "-subject", "-multivalue-rdn", "-precert", "-*",
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
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file
		"-key" .. parser({clink.filematches}),		-- Parameter Private key to use
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file
		"-config" .. parser({clink.filematches}), 	-- Parameter Request template file
		"-keyout" .. parser({clink.filematches}), 	-- Parameter File to send the key to
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}) 	-- Parameter Write random data to the specified file
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
		"-in" .. parser({clink.filematches}), 	-- Parameter Input file
		"-out" .. parser({clink.filematches}) 	-- Parameter Output file
	),
	"rsautl" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-pubin", "-certin", "-ssl", "-raw", "-pkcs", "-oaep",
		"-sign", "-verify", "-asn1parse", "-hexdump", "-x931", "-rev",
		"-encrypt", "-decrypt",
		"-passin",	-- Parameter Input file pass phrase source
		"-engine",	-- Parameter Use engine, possibly a hardware device
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file
		"-inkey" .. parser({clink.filematches}), 		-- Parameter Input key
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}) 	-- Parameter Write random data to the specified file
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
		"-cert" .. parser({clink.filematches}), 			-- Parameter Certificate file to use, PEM format assumed
		"-key" .. parser({clink.filematches}), 			-- Parameter Private key file to use, if not in -cert file
		"-CAfile" .. parser({clink.filematches}), 		-- Parameter PEM format file of CA's
		"-requestCAfile" .. parser({clink.filematches}), 	-- Parameter PEM format file of CA names to send to the server
		"-rand" .. parser({clink.filematches}), 			-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}), 		-- Parameter Write random data to the specified file
		"-sess_out" .. parser({clink.filematches}), 		-- Parameter File to write SSL session to
		"-sess_in" .. parser({clink.filematches}), 		-- Parameter File to read SSL session from
		"-CRL" .. parser({clink.filematches}), 			-- Parameter CRL file to use
		"-cert_chain" .. parser({clink.filematches}), 	-- Parameter Certificate chain file (in PEM format)
		"-chainCAfile" .. parser({clink.filematches}), 	-- Parameter CA file for certificate chain (PEM format)
		"-verifyCAfile" .. parser({clink.filematches}), 	-- Parameter CA file for certificate verification (PEM format)
		"-ssl_config" .. parser({clink.filematches}), 	-- Parameter Use specified configuration file
		"-xkey" .. parser({clink.filematches}), 			-- Parameter key for Extended certificates
		"-xcert" .. parser({clink.filematches}), 			-- Parameter cert for Extended certificates
		"-xchain" .. parser({clink.filematches}), 		-- Parameter chain for Extended certificates
		"-psk_session" .. parser({clink.filematches}),	-- Parameter File to read PSK SSL session from
		"-ctlogfile" .. parser({clink.filematches}), 		-- Parameter CT log list CONF file
		"-keylogfile" .. parser({clink.filematches}), 	-- Parameter Write TLS secrets to file
		"-early_data" .. parser({clink.filematches}), 	-- Parameter File to send as early data
		"-CApath" .. parser({clink.dirmatches}), 		-- Parameter PEM format directory of CA's
		"-chainCApath" .. parser({clink.dirmatches}), 	-- Parameter Use dir as cert store path to build CA certificate chain
		"-verifyCApath" .. parser({clink.dirmatches}) 	-- Parameter Use dir as cert store path to verify CA certificate
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
		"-cert" .. parser({clink.filematches}), 			-- Parameter Cert to use; default is server.pem
		"-key" .. parser({clink.filematches}), 			-- Parameter Private Key if not in -cert;
		"-dcert" .. parser({clink.filematches}), 			-- Parameter Second certificate file to use
		"-dhparam" .. parser({clink.filematches}), 		-- Parameter DH parameters file to use
		"-dkey" .. parser({clink.filematches}), 			-- Parameter Second private key file to use
		"-msgfile" .. parser({clink.filematches}), 		-- Parameter File to send output of -msg or -trace
		"-CAfile" .. parser({clink.filematches}), 		-- Parameter PEM format file of CA's
		"-cert2" .. parser({clink.filematches}), 			-- Parameter Cert to use for srvname; def isserver2.pem
		"-key2" .. parser({clink.filematches}), 			-- Parameter -Private Key to use if not in -cert2
		"-rand" .. parser({clink.filematches}), 			-- Parameter Load the file(s) into the rnd generator
		"-writerand" .. parser({clink.filematches}), 		-- Parameter Write random data to the specified file
		"-CRL" .. parser({clink.filematches}), 			-- Parameter CRL file to use
		"-cert_chain" .. parser({clink.filematches}), 	-- Parameter certificate chain file in PEM format
		"-dcert_chain" .. parser({clink.filematches}),	-- Parameter second cert chain file in PEM format
		"-chainCAfile" .. parser({clink.filematches}),	-- Parameter CA file for cert chain (PEM format)
		"-verifyCAfile" .. parser({clink.filematches}), 	-- Parameter CA file for cert verification (PEM format)
		"-status_file" .. parser({clink.filematches}), 	-- Parameter File containing DER encoded OCSP Response
		"-ssl_config" .. parser({clink.filematches}),	-- Parameter Configure SSL_CTX using the configuration 'val'
		"-xkey" .. parser({clink.filematches}), 			-- Parameter key for Extended certificates
		"-xcert" .. parser({clink.filematches}), 			-- Parameter cert for Extended certificates
		"-xchain" .. parser({clink.filematches}), 		-- Parameter chain for Extended certificates
		"-psk_session" .. parser({clink.filematches}), 	-- Parameter File to read PSK SSL session from
		"-srpvfile" .. parser({clink.filematches}), 		-- Parameter The verifier file for SRP
		"-keylogfile" .. parser({clink.filematches}), 	-- Parameter Write TLS secrets to file
		"-CApath" .. parser({clink.dirmatches}), 			-- Parameter PEM format directory of CA's
		"-chainCApath" .. parser({clink.dirmatches}), 	-- Parameter use path to build CA certificate chain
		"-verifyCApath" .. parser({clink.dirmatches}) 	-- Parameter use dir as path to verify CA certificate
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
		"-cert" .. parser({clink.filematches}), 		-- Parameter Cert file to use, PEM format assumed
		"-key" .. parser({clink.filematches}), 		-- Parameter File with key, PEM; default is -cert file
		"-cafile" .. parser({clink.filematches}), 	-- Parameter PEM format file of CA's
		"-CAfile" .. parser({clink.filematches}), 	-- Parameter PEM format file of CA's
		"-CApath" .. parser({clink.dirmatches}) 	-- Parameter PEM format directory of CA's
	),
	"sess_id" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-text", "-cert", "-noout",
		"-context",	-- Parameter Set the session ID context
		"-inform" .. parser({"PEM", "DER"}),
		"-outform" .. parser({"PEM", "DER", "NSS"}),
		"-in" .. parser({clink.filematches}), 	-- Parameter Input file - default stdin
		"-out" .. parser({clink.filematches}) 	-- Parameter Output file - default stdout
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
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-md" .. parser(digests),
		"-outform" .. parser({"SMIME", "PEM", "DER"}),
		"-certfile" .. parser({clink.filematches}), 	-- Parameter Other certificates file
		"-signer" .. parser({clink.filematches}), 	-- Parameter Signer certificate file
		"-recip" .. parser({clink.filematches}), 		-- Parameter Recipient certificate file for decryption
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file
		"-inkey" .. parser({clink.filematches}), 		-- Parameter Input private key (if not signer or recipient)
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file
		"-content" .. parser({clink.filematches}), 	-- Parameter Supply or override content for detached signature
		"-CAfile" .. parser({clink.filematches}), 	-- Parameter Trusted certificates file
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}), 	-- Parameter Write random data to the specified file
		"-CApath" .. parser({clink.dirmatches})	 	-- Parameter Trusted certificates directory
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
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}) 	-- Parameter Write random data to the specified file
	),
	"spkac" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-noout", "-pubkey", "-verify",
		"-passin",		-- Parameter Input file pass phrase source
		"-challenge",	-- Parameter Challenge string
		"-spkac",		-- Parameter Alternative SPKAC name
		"-spksect",		-- Parameter Specify the name of an SPKAC-dedicated section of configuration
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-keyform" .. parser({"PEM", "DER", "ENGINE"}),
		"-in" .. parser({clink.filematches}),		-- Parameter Input file
		"-out" .. parser({clink.filematches}),	-- Parameter Output file
		"-key" .. parser({clink.filematches}) 	-- Parameter Create SPKAC using private key
	),
	"srp" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-verbose", "-add", "-modify", "-delete", "-list",
		"-name",		-- Parameter The particular srp definition to use
		"-gn",			-- Parameter Set g and N values to be used for new verifier
		"-userinfo",	-- Parameter Additional info to be set for user
		"-passin",		-- Parameter Input file pass phrase source
		"-passout",		-- Parameter Output file pass phrase source
		"-engine",		-- Parameter Use engine, possibly a hardware device
		"-config" .. parser({clink.filematches}), 	-- Parameter A config file
		"-srpvfile" .. parser({clink.filematches}), 	-- Parameter The srp verifier file name
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}) 	-- Parameter Write random data to the specified file
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
 		"-out" .. parser({clink.filematches}) 	-- Parameter Output file - default stdout
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
			"-config" .. parser({clink.filematches}), 	-- Parameter Configuration file
			"-data" .. parser({clink.filematches}), 		-- Parameter File to hash
			"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
			"-writerand" .. parser({clink.filematches}), 	-- Parameter Write random data to the specified file
			"-in" .. parser({clink.filematches}), 		-- Parameter Input file
			"-out" .. parser({clink.filematches}), 		-- Parameter Output file
			"-queryfile" .. parser({clink.filematches}), 	-- Parameter File containing a TS query
			"-inkey" .. parser({clink.filematches}), 		-- Parameter File with private key for reply
			"-signer" .. parser({clink.filematches}), 	-- Parameter Signer certificate file
			"-chain" .. parser({clink.filematches}), 		-- Parameter File with signer CA chain
			"-CAfile" .. parser({clink.filematches}), 	-- Parameter File with trusted CA certs
			"-untrusted" .. parser({clink.filematches}), 	-- Parameter File with untrusted certs
			"-CApath" .. parser({clink.dirmatches}), 	-- Parameter Path to trusted CA files
		}),
		"-reply" .. parser({
			"-no_nonce", "-cert", "-token_in", "-token_out", "-text", "-*",
			"-section",		-- Parameter Section to use within config file
			"-digest",		-- Parameter Digest (as a hex string)
			"-tspolicy",	-- Parameter Policy OID to use
			"-passin",		-- Parameter Input file pass phrase source
			"-engine",		-- Parameter Use engine, possibly a hardware device
			"-config" .. parser({clink.filematches}), 	-- Parameter Configuration file
			"-data" .. parser({clink.filematches}), 		-- Parameter File to hash
			"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
			"-writerand" .. parser({clink.filematches}), 	-- Parameter Write random data to the specified file
			"-in" .. parser({clink.filematches}), 		-- Parameter Input file
			"-out" .. parser({clink.filematches}), 		-- Parameter Output file
			"-queryfile" .. parser({clink.filematches}), 	-- Parameter File containing a TS query
			"-inkey" .. parser({clink.filematches}), 		-- Parameter File with private key for reply
			"-signer" .. parser({clink.filematches}), 	-- Parameter Signer certificate file
			"-chain" .. parser({clink.filematches}), 		-- Parameter File with signer CA chain
			"-CAfile" .. parser({clink.filematches}), 	-- Parameter File with trusted CA certs
			"-untrusted" .. parser({clink.filematches}), 	-- Parameter File with untrusted certs
			"-CApath" .. parser({clink.dirmatches}), 	-- Parameter Path to trusted CA files
		}),
		"-verify" .. parser({
			-- common part (like -query  and -reply)
			"-no_nonce", "-cert", "-token_in", "-token_out", "-text", "-*",
			"-section",		-- Parameter Section to use within config file
			"-digest",		-- Parameter Digest (as a hex string)
			"-tspolicy",	-- Parameter Policy OID to use
			"-passin",		-- Parameter Input file pass phrase source
			"-engine",		-- Parameter Use engine, possibly a hardware device
			"-config" .. parser({clink.filematches}), 	-- Parameter Configuration file
			"-data" .. parser({clink.filematches}), 		-- Parameter File to hash
			"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into the random number generator
			"-writerand" .. parser({clink.filematches}), 	-- Parameter Write random data to the specified file
			"-in" .. parser({clink.filematches}), 		-- Parameter Input file
			"-out" .. parser({clink.filematches}), 		-- Parameter Output file
			"-queryfile" .. parser({clink.filematches}), 	-- Parameter File containing a TS query
			"-inkey" .. parser({clink.filematches}), 		-- Parameter File with private key for reply
			"-signer" .. parser({clink.filematches}), 	-- Parameter Signer certificate file
			"-chain" .. parser({clink.filematches}), 		-- Parameter File with signer CA chain
			"-CAfile" .. parser({clink.filematches}), 	-- Parameter File with trusted CA certs
			"-untrusted" .. parser({clink.filematches}), 	-- Parameter File with untrusted certs
			"-CApath" .. parser({clink.dirmatches}), 	-- Parameter Path to trusted CA files
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
		"-CAfile" .. parser({clink.filematches}), 	-- Parameter A file of trusted certificates
		"-CApath" .. parser({clink.filematches}), 	-- Parameter A directory of trusted certificates
		"-untrusted" .. parser({clink.filematches}), 	-- Parameter A file of untrusted certificates
		"-trusted" .. parser({clink.filematches}), 	-- Parameter A file of trusted certificates
		"-CRLfile" .. parser({clink.filematches}) 	-- Parameter File containing one or more CRL's (in PEM format) to load
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
		"-in" .. parser({clink.filematches}), 		-- Parameter Input file - default stdin
		"-out" .. parser({clink.filematches}), 		-- Parameter Output file - default stdout
		"-CA" .. parser({clink.filematches}), 		-- Parameter Set the CA certificate, must be PEM format
		"-CAkey" .. parser({clink.filematches}), 		-- Parameter The CA key as PEM; if not in CAfile
		"-CAserial" .. parser({clink.filematches}), 	-- Parameter Serial file
		"-extfile" .. parser({clink.filematches}), 	-- Parameter File with X509V3 extensions to add
		"-signkey" .. parser({clink.filematches}),		-- Parameter Self sign cert with arg
		"-rand" .. parser({clink.filematches}), 		-- Parameter Load the file(s) into random number generator
		"-writerand" .. parser({clink.filematches}), 	-- Parameter Write random data to the specified file
		"-force_pubkey" .. parser({clink.filematches}) -- Parameter Force the Key to put inside certificate
	)
}

local openSSL30CommandLine = {
	"cmp" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-san_nodefault", "-policy_oids_critical",
		"-implicit_confirm", "-disable_confirm", "-ignore_keyusage",
		"-unprotected_errors", "-unprotected_requests", "-tls_used", "-batch",
		"-reqin_new_tid", "-use_mock_srv", "-grant_implicitconf", "-send_error",
		"-send_unprotected", "-send_unprot_err", "-accept_unprotected",
		"-accept_unprot_err", "-accept_raverified", "-ignore_critical",
		"-issuer_checks", "-crl_check", "-crl_check_all", "-policy_check",
		"-explicit_policy", "-inhibit_any", "-inhibit_map", "-x509_strict",
		"-extended_crl", "-use_deltas", "-policy_print", "-check_ss_sig",
		"-trusted_first", "-suiteB_128_only", "-suiteB_128", "-suiteB_192",
		"-partial_chain", "-no_alt_chains", "-no_check_time", "-allow_proxy_certs",
		"-section", 	-- Parameter val Section(s) in config file to get options from. "" = 'default'. Default 'cmp'
		"-cmd", 		-- Parameter val CMP request to send: ir/cr/kur/p10cr/rr/genm
		"-infotype", 	-- Parameter val InfoType name for requesting specific info in genm, e.g. 'signKeyPairTypes'
		"-geninfo", 	-- Parameter val generalInfo integer values to place in request PKIHeader with given OID specified in the form <OID>:int:<n>, e.g. "1.2.3.4:int:56789"
		"-mac",			-- Parameter val MAC algorithm to use in PBM-based message protection. Default "hmac-sha1"
		"-newkey", 		-- Parameter val Private or public key for the requested cert. Default: CSR key or client key
		"-newkeypass", 	-- Parameter val New private key pass phrase source
		"-subject", 	-- Parameter val Distinguished Name (DN) of subject to use in the requested cert template For kur, default is subject of -csr arg or else of reference cert (see -oldcert) this default is used for ir and cr only if no Subject Alt Names are set
		"-issuer", 		-- Parameter val DN of the issuer to place in the requested certificate template also used as recipient if neither -recipient nor -srvcert are given
		"-days", 		-- Parameter nonneg Requested validity time of the new certificate in number of days
		"-reqexts", 	-- Parameter val Name of config file section defining certificate request extensions. Augments or replaces any extensions contained CSR given with -csr
		"-sans", 		-- Parameter val Subject Alt Names (IPADDR/DNS/URI) to add as (critical) cert req extension
		"-policies", 	-- Parameter val Name of config file section defining policies certificate request extension
		"-policy_oids", -- Parameter val Policy OID(s) to add as policies certificate request extension
		"-popo", 		-- Parameter int Proof-of-Possession (POPO) method to use for ir/cr/kur where -1 = NONE, 0 = RAVERIFIED, 1 = SIGNATURE (default), 2 = KEYENC
		"-out_trusted", -- Parameter val Certificates to trust when verifying newly enrolled certificates
		"-oldcert", 	-- Parameter val Certificate to be updated (defaulting to -cert) or to be revoked in rr; also used as reference (defaulting to -cert) for subject DN and SANs. Its issuer is used as recipient unless -recipient, -srvcert, or -issuer given
		"-server",		-- Parameter val [http[s]://]address[:port][/path] of CMP server. Default port 80 or 443. address may be a DNS name or an IP address; path can be overridden by -path
		"-path", 		-- Parameter val HTTP path (aka CMP alias) at the CMP server. Default from -server, else "/"
		"-proxy", 		-- Parameter val [http[s]://]address[:port][/path] of HTTP(S) proxy to use; path is ignored
		"-no_proxy", 	-- Parameter val List of addresses of servers not to use HTTP(S) proxy for Default from environment variable 'no_proxy', else 'NO_PROXY', else none
		"-recipient", 	-- Parameter val DN of CA. Default: subject of -srvcert, -issuer, issuer of -oldcert or -cert
		"-msg_timeout", -- Parameter nonneg Number of seconds allowed per CMP message round trip, or 0 for infinite
		"-total_timeout",	-- Parameter nonneg Overall time an enrollment incl. polling may take. Default 0 = infinite
		"-trusted", 		-- Parameter val Certificates to trust as chain roots when verifying signed CMP responses unless -srvcert is given
		"-untrusted", 		-- Parameter val Intermediate CA certs for chain construction for CMP/TLS/enrolled certs
		"-srvcert", 		-- Parameter val Server cert to pin and trust directly when verifying signed CMP responses
		"-expect_sender", 	-- Parameter val DN of expected sender of responses. Defaults to subject of -srvcert, if any
		"-ref", 			-- Parameter val Reference value to use as senderKID in case no -cert is given
		"-secret",	 		-- Parameter val Prefer PBM (over signatures) for protecting msgs with given password source
		"-cert", 			-- Parameter val Client's CMP signer certificate; its public key must match the -key argument This also used as default reference for subject DN and SANs. Any further certs included are appended to the untrusted certs
		"-own_trusted", 	-- Parameter val Optional certs to verify chain building for own CMP signer cert
		"-key", 			-- Parameter val CMP signer private key, not used when -secret given
		"-keypass", 		-- Parameter val Client private key (and cert and old cert) pass phrase source
		"-extracerts", 		-- Parameter val Certificates to append in extraCerts field of outgoing messages. This can be used as the default CMP signer cert chain to include
		"-otherpass", 		-- Parameter val Pass phrase source potentially needed for loading certificates of others
		"-engine", 			-- Parameter val Use crypto engine with given identifier, possibly a hardware device. Engines may also be defined in OpenSSL config file engine section.
		"-provider", 		-- Parameter val Provider to load (can be specified multiple times)
		"-propquery", 		-- Parameter val Property query used when fetching algorithms
		"-tls_cert",		-- Parameter val Client's TLS certificate. May include chain to be provided to TLS server
		"-tls_key", 		-- Parameter val Private key for the client's TLS certificate
		"-tls_keypass", 	-- Parameter val Pass phrase source for the client's private TLS key (and TLS cert)
		"-tls_extra", 		-- Parameter val Extra certificates to provide to TLS server during TLS handshake
		"-tls_trusted", 	-- Parameter val Trusted certificates to use for verifying the TLS server certificate; this implies host name validation
		"-tls_host", 		-- Parameter val Address to be checked (rather than -server) during TLS host name validation
		"-repeat", 			-- Parameter +int Invoke the transaction the given positive number of times. Default 1
		"-port", 			-- Parameter val Act as HTTP mock server listening on given port
		"-max_msgs", 		-- Parameter nonneg max number of messages handled by HTTP mock server. Default: 0 = unlimited
		"-srv_ref", 		-- Parameter val Reference value to use as senderKID of server in case no -srv_cert is given
		"-srv_secret", 		-- Parameter val Password source for server authentication with a pre-shared key (secret)
		"-srv_cert", 		-- Parameter val Certificate of the server
		"-srv_key", 		-- Parameter val Private key used by the server for signing messages
		"-srv_keypass", 	-- Parameter val Server private key (and cert) pass phrase source
		"-srv_trusted", 	-- Parameter val Trusted certificates for client authentication
		"-srv_untrusted", 	-- Parameter val Intermediate certs that may be useful for verifying CMP protection
		"-rsp_cert", 		-- Parameter val Certificate to be returned as mock enrollment result
		"-rsp_extracerts", 	-- Parameter val Extra certificates to be included in mock certification responses
		"-rsp_capubs", 		-- Parameter val CA certificates to be included in mock ip response
		"-poll_count", 		-- Parameter nonneg Number of times the client must poll before receiving a certificate
		"-check_after", 	-- Parameter nonneg The check_after value (time to wait) to include in poll response
		"-failurebits", 	-- Parameter nonneg Number representing failure bits to include in server response, 0..2^27 - 1
		"-statusstring", 	-- Parameter val Status string to be included in server response
		"-policy", 			-- Parameter val adds policy to the acceptable policy set
		"-purpose", 		-- Parameter val certificate chain purpose
		"-verify_name", 	-- Parameter val verification policy name
		"-verify_depth", 	-- Parameter int chain depth limit
		"-auth_level", 		-- Parameter int chain authentication security level
		"-attime", 			-- Parameter intmax verification epoch time
		"-verify_hostname", -- Parameter val expected peer hostname
		"-verify_email", 	-- Parameter val expected peer email
		"-verify_ip", 		-- Parameter val expected peer IP address
		"-digest" .. parser(digests), 			-- Parameter val Digest to use in message protection and POPO signatures. Default "sha256"
		"-certform" .. parser({"PEM", "DER"}), 	-- Parameter val Format (PEM or DER) to use when saving a certificate to a file. Default PEM
		"-keyform" .. parser({"ENGINE"}), 		-- Parameter val Format of the key input (ENGINE, other values ignored)
		"-pkistatus" .. parser({"0", "1", "2", "3", "4", "5", "6"}), -- Parameter nonneg PKIStatus to be included in server response. Possible values: 0..6
		"-failure" .. parser({"0", "1", "2", "3", "4", "5", "6", "7",
							 "8", "9", "10", "11", "12", "13", "14",
							 "15", "16", "17", "18", "19", "20", "21",
							 "22", "23", "24", "25", "26"}), -- Parameter nonneg A single failure info bit number to include in server response, 0..26
		"-keep_alive" .. parser({"0", "1", "2"}), 			-- Parameter nonneg Persistent HTTP connections. 0: no, 1 (the default): request, 2: require
		"-verbosity" .. parser({"3", "4", "6", "7", "8"}),	-- Parameter nonneg Log level; 3=ERR, 4=WARN, 6=INFO, 7=DEBUG, 8=TRACE. Default 6 = INFO
		"-revreason" .. parser({"-1", "0", "1", "2", "3", "4", "5", "6", "8", "9", "10"}),	-- Parameter int Reason code to include in revocation request (rr); possible values: 0..6, 8..10 (see RFC5280, 5.3.1) or -1. Default -1 = none included
		"-extracertsout" .. parser({clink.filematches}), 	-- Parameter val File to save extra certificates received in the extraCerts field
		"-cacertsout" .. parser({clink.filematches}), 		-- Parameter val File to save CA certificates received in the caPubs field of 'ip' messages
		"-rand" .. parser({clink.filematches}), 			-- Parameter val Load the given file(s) into the random number generator
		"-writerand" .. parser({clink.filematches}), 		-- Parameter outfile Write random data to the specified file
		"-reqin" .. parser({clink.filematches}), 			-- Parameter val Take sequence of CMP requests from file(s)
		"-reqout" .. parser({clink.filematches}), 			-- Parameter val Save sequence of CMP requests to file(s)
		"-rspin" .. parser({clink.filematches}), 			-- Parameter val Process sequence of CMP responses provided in file(s), skipping server
		"-rspout" .. parser({clink.filematches}), 			-- Parameter val Save sequence of CMP responses to file(s)
		"-csr" .. parser({clink.filematches}), 				-- Parameter val PKCS#10 CSR file in PEM or DER format to convert or to use in p10cr
		"-certout" .. parser({clink.filematches}), 			-- Parameter val File to save newly enrolled certificate
		"-chainout" .. parser({clink.filematches}), 		-- Parameter val File to save the chain of newly enrolled certificate
		"-config" .. parser({clink.filematches}),			-- Parameter val Configuration file to use. "" = none. Default from env variable OPENSSL_CONF
		"-provider-path" .. parser({clink.dirmatches}) 		-- Parameter val Provider load path (must be before 'provider' argument if required)
	),
	"fipsinstall" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-verify", "-no_conditional_errors", "-no_security_checks",
		"-self_test_onload", "-noout", "-quiet",
		"-provider_name", 	-- Parameter val FIPS provider name
		"-section_name", 	-- Parameter val FIPS Provider config section name (optional)
		"-mac_name", 		-- Parameter val MAC name
		"-macopt", 			-- Parameter val MAC algorithm parameters in n:v form. See 'PARAMETER NAMES' in the EVP_MAC_ docs
		"-corrupt_desc", 	-- Parameter val Corrupt a self test by description
		"-corrupt_type", 	-- Parameter val Corrupt a self test by type
		"-module" .. parser({clink.filematches}),		-- Parameter infile File name of the provider module
		"-in" .. parser({clink.filematches}), 			-- Parameter infile Input config file, used when verifying
		"-out" .. parser({clink.filematches}), 			-- Parameter outfile Output config file, used when generating
		"-config" .. parser({clink.filematches})		-- Parameter infile The parent config to verify
	),
	"info" .. parser({}, -- empty {}: don't suggest any positional args
		"-help", "-dsoext", "-dirnamesep", "-listsep", "-seeds", "-cpusettings",
 		"-configdir" .. parser({clink.dirmatches}), 	-- Default configuration file directory
 		"-enginesdir" .. parser({clink.dirmatches}), 	-- Default engine module directory
 		"-modulesdir"  .. parser({clink.dirmatches}) 	-- Default module directory (other than engine modules)
	),
	"kdf" .. parser(
		"-help", "-binary",
		"-kdfopt", 		-- Parameter val KDF algorithm control parameters in n:v form
		"-cipher" .. parser(ciphers), 		-- Parameter val Cipher
		"-mac", 		-- Parameter val MAC
		"-keylen", 		-- Parameter val The size of the output derived key
		"-provider", 	-- Parameter val Provider to load (can be specified multiple times)
		"-propquery", 	-- Parameter val Property query used when fetching algorithms	),
		"-digest" .. parser(digests), 			-- Parameter val Digest
		"-out" .. parser({clink.filematches}), 	-- Parameter outfile Output to filename rather than stdout
		"-provider-path" .. parser({clink.dirmatches}) -- Parameter val Provider load path (must be before 'provider' argument if required)
	),
	"mac" .. parser(
		"-help", "-binary",
		"-macopt", 		-- Parameter val MAC algorithm parameters in n:v form
		"-cipher" .. parser(ciphers), 		-- Parameter val Cipher
		"-provider", 	-- Parameter val Provider to load (can be specified multiple times)
		"-propquery", 	-- Parameter val Property query used when fetching algorithms
		"-digest" .. parser(digests), 					-- Parameter val Digest
		"-in" .. parser({clink.filematches}), 			-- Parameter infile Input file to MAC (default is stdin)
		"-out" .. parser({clink.filematches}), 			-- Parameter outfile Output to filename rather than stdout
		"-provider-path" .. parser({clink.dirmatches}) 	-- Parameter val Provider load path (must be before 'provider' argument if required)
	)
}

local openSSL35CommandLine = {
	"skeyutl" .. parser(
		"-help", "-gen-key",
		"-skeyopt",		-- Parameter val Key options as opt:value for opaque keys handling
		"-skeymgmt", 	-- Parameter val Symmetric key management name for opaque keys handling
		"-cipher" .. parser(ciphers), 		-- Parameter val The cipher to generate key for
		"-provider", 	-- Parameter val Provider to load (can be specified multiple times)
		"-provparam", 	-- Parameter val Set a provider key-value parameter
		"-propquery", 	-- Parameter val Property query used when fetching algorithms
		"-provider-path" .. parser({clink.dirmatches}) 		-- Parameter val Provider load path (must be before 'provider' argument if required)
	)
}

local openssl_parser

if getOpenSSLVersion() == "1.1" then
	openssl_parser = parser({openSSL10CommandLine})
end

if getOpenSSLVersion() == "3.0" then
	openssl_parser = parser({openSSL10CommandLine, openSSL30CommandLine})
end

if getOpenSSLVersion() == "3.1" then
	openssl_parser = parser({openSSL10CommandLine, openSSL30CommandLine})
end

if getOpenSSLVersion() == "3.2" then
	openssl_parser = parser({openSSL10CommandLine, openSSL30CommandLine})
end

if getOpenSSLVersion() == "3.3" then
	openssl_parser = parser({openSSL10CommandLine, openSSL30CommandLine})
end

if getOpenSSLVersion() == "3.4" then
	openssl_parser = parser({openSSL10CommandLine, openSSL30CommandLine})
end

if getOpenSSLVersion() == "3.5" then
	openssl_parser = parser({openSSL10CommandLine, openSSL30CommandLine, openSSL35CommandLine})
end

clink.arg.register_parser("openssl", openssl_parser)
