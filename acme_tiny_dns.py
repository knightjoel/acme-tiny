#!/usr/bin/env python
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
import requests
try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2

#DEFAULT_CA = "https://acme-staging.api.letsencrypt.org"
DEFAULT_CA = "https://acme-v01.api.letsencrypt.org"

DNS_API_URL = "https://api.cloudns.net/"

CONF = os.path.join(os.environ["HOME"], ".acme_tiny_dns.conf")

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def get_crt(account_key, csr, dns_zone, log=LOGGER, CA=DEFAULT_CA):
    # helper function base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    # parse account key to get public key
    log.info("Parsing account key...")
    proc = subprocess.Popen(["openssl", "rsa", "-in", account_key, "-noout", "-text"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    header = {
        "alg": "RS256",
        "jwk": {
            "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }
    accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # helper function make signed requests
    def _send_signed_request(url, payload):
        payload64 = _b64(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        protected["nonce"] = urlopen(CA + "/directory").headers['Replay-Nonce']
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", account_key],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate("{0}.{1}".format(protected64, payload64).encode('utf8'))
        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        data = json.dumps({
            "header": header, "protected": protected64,
            "payload": payload64, "signature": _b64(out),
        })
        try:
            resp = urlopen(url, data.encode('utf8'))
            return resp.getcode(), resp.read()
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__)()

    # find domains
    log.info("Parsing CSR...")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("Error loading {0}: {1}".format(csr, err))
    domains = set([])
    common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", out.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE|re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])

    # get the certificate domains and expiration
    log.info("Registering account...")
    code, result = _send_signed_request(CA + "/acme/new-reg", {
        "resource": "new-reg",
        "agreement": "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf",
    })
    if code == 201:
        log.info("Registered!")
    elif code == 409:
        log.info("Already registered!")
    else:
        raise ValueError("Error registering: {0} {1}".format(code, result))

    try:
        with open(CONF) as conf_file:
            local_config = json.load(conf_file)
    except ValueError:
        log.error("Could not parse config file ({}). Is it valid JSON?"
                  .format(CONF))
        sys.exit(1)

    # verify each domain
    for domain in domains:
        log.info("Verifying {0}...".format(domain))

        # get new challenge
        code, result = _send_signed_request(CA + "/acme/new-authz", {
            "resource": "new-authz",
            "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
            raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

        # create the dns entry
        challenge = [c for c in json.loads(result.decode('utf8'))['challenges'] 
                        if c['type'] == "dns-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        keyauthhash = _b64(hashlib.sha256(keyauthorization.encode('utf8')).digest())
        # the cloudns api expects just the host part and not host.zone in the
        # 'host' key.
        if dns_zone != domain:
            dns_host = domain[0:domain.find(dns_zone)-1]
        else:
            dns_host = ""
        # XXX debug
        log.info("Adding TXT record {} for keyauth {}.{}\n"
                 .format(keyauthhash, token, thumbprint))
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        dns_body = {
            'sub-auth-user': local_config['cloudns_auth_user'],
            'auth-password': local_config['cloudns_auth_password'],
            'domain-name': dns_zone,
            'host': "_acme-challenge." + dns_host,
            'record': keyauthhash,
            'ttl': 300
        }

        # list records; get the record-id of the acme-challenge record
        try:
            r = requests.get("{}{}".format(DNS_API_URL, "/dns/records.json"),
                             headers = headers,
                             params = dns_body)
        except requests.exceptions.RequestException as e:
            raise ValueError("Couldn't get list of DNS records: {}: {}"
                    .format(getattr(e, "code", None),
                            getattr(e, "read", e.__str__)))

        # FYI, cloudns will return 200 even if auth fails
        if r.status_code != 200:
            raise ValueError("DNS API request returned code {}: {}"
                                 .format(code, result))
        try:
            resp = json.loads(r.text)
        except ValueError as e:
            raise ValueError("Did not get a valid JSON response from DNS API")

        if type(resp) is list and len(resp) == 0:
            raise ValueError(("DNS record '{}' does not exist and must be"
                                  " created".format(dns_body['host'])))
        if 'status' in resp.keys() and resp['status'] == 'Failed':
            raise ValueError("DNS API called failed: {}"
                                 .format(resp['statusDescription']))

        # update the record
        try:
            dns_body.update({"record-id": resp.keys()[0]})
        except ValueError as e:
            raise ValueError("Could not find DNS record to update: {}: {}"
                    .format(getattr(e, "code", None),
                            getattr(e, "read", e.__str__)))
        try:
            r = requests.post("{}{}".format(DNS_API_URL,
                                           "/dns/mod-record.json"),
                             headers = headers,
                             data = dns_body)
        except requests.exceptions.RequestException as e:
            raise ValueError("Failed to update DNS record {}: {}: {}"
                    .format(dns_body['host'],
                            getattr(e, "code", None),
                            getattr(e, "read", e.__str__)))

        # FYI, cloudns will return 200 even if auth fails
        if r.status_code != 200:
            raise ValueError("DNS API request returned code {}: {}"
                                 .format(code, result))
        try:
            resp = json.loads(r.text)
        except ValueError as e:
            raise ValueError("Did not get a valid JSON response from DNS API")

        if 'status' in resp.keys() and resp['status'] == 'Failed':
            raise ValueError("DNS API called failed: {}"
                                 .format(resp['statusDescription']))

        log.info("DNS record created. Pausing so DNS can settle...")
        time.sleep(60)

        # notify challenge are met
        code, result = _send_signed_request(challenge['uri'], {
            "resource": "challenge",
            "keyAuthorization": keyauthorization,
        })
        if code != 202:
            raise ValueError("Error triggering challenge: {0} {1}".format(code, result))

        # wait for challenge to be verified
        while True:
            try:
                resp = urlopen(challenge['uri'])
                challenge_status = json.loads(resp.read().decode('utf8'))
            except IOError as e:
                raise ValueError("Error checking challenge: {0} {1}".format(
                    e.code, json.loads(e.read().decode('utf8'))))
            if challenge_status['status'] == "pending":
                time.sleep(2)
            elif challenge_status['status'] == "valid":
                log.info("{0} verified!".format(domain))
                # XXX should remove the DNS record at this point but the
                # GoDaddy API strangely doesn't support this
                break
            else:
                raise ValueError("{0} challenge did not pass: {1}".format(
                    domain, challenge_status))

    # get the new certificate
    log.info("Signing certificate...")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    csr_der, err = proc.communicate()
    code, result = _send_signed_request(CA + "/acme/new-cert", {
        "resource": "new-cert",
        "csr": _b64(csr_der),
    })
    if code != 201:
        raise ValueError("Error signing certificate: {0} {1}".format(code, result))

    # return signed certificate!
    log.info("Certificate signed!")
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64)))

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from
            Let's Encrypt using the ACME protocol. It will need to be run on your server
            and have access to your private account key, so PLEASE READ THROUGH IT! It's
            only ~200 lines, so it won't take long.

            ===Example Usage===
            python acme_tiny_dns.py --account-key ./account.key --csr ./domain.csr --dns-zone domain.com > signed.crt
            ===================

            ===Example Crontab Renewal (once per month)===
            0 0 1 * * python /path/to/acme_tiny_dns.py --account-key /path/to/account.key --csr /path/to/domain.csr --dns-zone domain.com > /path/to/signed.crt 2>> /var/log/acme_tiny.log
            ==============================================
            """)
    )
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--dns-zone", required=True, help="the name of the DNS zone to use for ownership verification")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("--ca", default=DEFAULT_CA, help="certificate authority, default is Let's Encrypt")

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)

    if not os.path.isfile(CONF):
        LOGGER.error("Config file {} does not exist".format(CONF))
        sys.exit(1)

    signed_crt = get_crt(args.account_key, args.csr, args.dns_zone, log=LOGGER, CA=args.ca)
    sys.stdout.write(signed_crt)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
