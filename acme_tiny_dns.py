#!/usr/bin/env python3
# Copyright Daniel Roesler, under MIT license, see LICENSE at github.com/diafygi/acme-tiny

import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
import requests
try:
    from urllib.request import urlopen, Request # Python 3
except ImportError:
    from urllib2 import urlopen, Request # Python 2

DEFAULT_CA = "https://acme-v02.api.letsencrypt.org" # DEPRECATED! USE DEFAULT_DIRECTORY_URL INSTEAD
DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"

DNS_API_URL = "https://api.cloudns.net"

CONF = os.path.join(os.environ["HOME"], ".acme_tiny_dns.conf")

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def get_crt(account_key, csr, dns_zone, log=LOGGER, CA=DEFAULT_CA, disable_check=False, directory_url=DEFAULT_DIRECTORY_URL, contact=None):
    directory, acct_headers, alg, jwk = None, None, None, None # global variables

    # helper functions - base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    # helper function - run external commands
    def _cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
        proc = subprocess.Popen(cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(cmd_input)
        if proc.returncode != 0:
            raise IOError("{0}\n{1}".format(err_msg, err))
        return out

    # helper function - make request and automatically parse json response
    def _do_request(url, data=None, err_msg="Error", depth=0):
        try:
            resp = urlopen(Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acme-tiny"}))
            resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
        except IOError as e:
            resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
            code, headers = getattr(e, "code", None), {}
        try:
            resp_data = json.loads(resp_data) # try to parse json results
        except ValueError:
            pass # ignore json parsing errors
        if depth < 100 and code == 400 and resp_data['type'] == "urn:ietf:params:acme:error:badNonce":
            raise IndexError(resp_data) # allow 100 retrys for bad nonces
        if code not in [200, 201, 204]:
            raise ValueError("{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, code, resp_data))
        return resp_data, code, headers

    # helper function - make signed requests
    def _send_signed_request(url, payload, err_msg, depth=0):
        payload64 = "" if payload is None else _b64(json.dumps(payload).encode('utf8'))
        new_nonce = _do_request(directory['newNonce'])[2]['Replay-Nonce']
        protected = {"url": url, "alg": alg, "nonce": new_nonce}
        protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers['Location']})
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        protected_input = "{0}.{1}".format(protected64, payload64).encode('utf8')
        out = _cmd(["openssl", "dgst", "-sha256", "-sign", account_key], stdin=subprocess.PIPE, cmd_input=protected_input, err_msg="OpenSSL Error")
        data = json.dumps({"protected": protected64, "payload": payload64, "signature": _b64(out)})
        try:
            return _do_request(url, data=data.encode('utf8'), err_msg=err_msg, depth=depth)
        except IndexError: # retry bad nonces (they raise IndexError)
            return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

    # helper function - poll until complete
    def _poll_until_not(url, pending_statuses, err_msg):
        result, t0 = None, time.time()
        while result is None or result['status'] in pending_statuses:
            assert (time.time() - t0 < 3600), "Polling timeout" # 1 hour timeout
            time.sleep(0 if result is None else 2)
            result, _, _ = _send_signed_request(url, None, err_msg)
        return result

    try:
        with open(CONF) as conf_file:
            local_config = json.load(conf_file)
    except ValueError:
        raise ValueError("Could not parse config file ({}). Is it valid JSON?"
                  .format(CONF))

    # parse account key to get public key
    log.info("Parsing account key...")
    out = _cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="OpenSSL Error")
    pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(pub_pattern, out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    alg = "RS256"
    jwk = {
        "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
    }
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # find domains
    log.info("Parsing CSR...")
    out = _cmd(["openssl", "req", "-in", csr, "-noout", "-text"], err_msg="Error loading {0}".format(csr))
    domains = set([])
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE|re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    log.info("Found domains: {0}".format(", ".join(domains)))

    # get the ACME directory of urls
    log.info("Getting directory...")
    directory_url = CA + "/directory" if CA != DEFAULT_CA else directory_url # backwards compatibility with deprecated CA kwarg
    directory, _, _ = _do_request(directory_url, err_msg="Error getting directory")
    log.info("Directory found!")

    # create account, update contact details (if any), and set the global key identifier
    log.info("Registering account...")
    reg_payload = {"termsOfServiceAgreed": True}
    account, code, acct_headers = _send_signed_request(directory['newAccount'], reg_payload, "Error registering")
    log.info("Registered!" if code == 201 else "Already registered!")
    if contact is not None:
        account, _, _ = _send_signed_request(acct_headers['Location'], {"contact": contact}, "Error updating contact details")
        log.info("Updated contact details:\n{0}".format("\n".join(account['contact'])))

    # create a new order
    log.info("Creating new order...")
    order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
    order, _, order_headers = _send_signed_request(directory['newOrder'], order_payload, "Error creating new order")
    log.info("Order created!")

    # get the authorizations that need to be completed
    for auth_url in order['authorizations']:
        authorization, _, _ = _send_signed_request(auth_url, None, "Error getting challenges")
        domain = authorization['identifier']['value']
        log.info("Verifying {0}...".format(domain))

        # find the dns-01 challenge and write the challenge file
        challenge = [c for c in authorization['challenges'] if c['type'] == "dns-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        keyauthhash = _b64(hashlib.sha256(keyauthorization.encode('utf8')).digest())
        # the cloudns api expects just the host part and not host.zone in the
        # 'host' key.
        if dns_zone != domain:
            dns_host = '_acme-challenge.' + domain[0:domain.find(dns_zone)-1]
        else:
            # No trailing '.'
            dns_host = '_acme-challenge'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        dns_body = {
            'sub-auth-user': local_config['cloudns_auth_user'],
            'auth-password': local_config['cloudns_auth_password'],
            'domain-name': dns_zone,
            'host': dns_host,
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
            raise ValueError("DNS API call failed: {}"
                                 .format(resp['statusDescription']))

        # update the record
        try:
            dns_body.update({"record-id": list(resp.keys())[0]})
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
        time.sleep(120)

        # say the challenge is done
        _send_signed_request(challenge['url'], {}, "Error submitting challenges: {0}".format(domain))
        authorization = _poll_until_not(auth_url, ["pending"], "Error checking challenge status for {0}".format(domain))
        if authorization['status'] != "valid":
            raise ValueError("Challenge did not pass for {0}: {1}".format(domain, authorization))
        log.info("{0} verified!".format(domain))

    # finalize the order with the csr
    log.info("Signing certificate...")
    csr_der = _cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
    _send_signed_request(order['finalize'], {"csr": _b64(csr_der)}, "Error finalizing order")

    # poll the order to monitor when it's done
    order = _poll_until_not(order_headers['Location'], ["pending", "processing"], "Error checking order status")
    if order['status'] != "valid":
        raise ValueError("Order failed: {0}".format(order))

    # download the certificate
    certificate_pem, _, _ = _send_signed_request(order['certificate'], None, "Certificate download failed")
    log.info("Certificate signed!")
    return certificate_pem

def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            ===Example Usage===
            This script automates the process of getting a signed TLS certificate from
            Let's Encrypt using the ACME protocol. It will need to be run on your server
            and have access to your private account key, so PLEASE READ THROUGH IT! It's
            only ~200 lines, so it won't take long.

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
    parser.add_argument("--disable-check", default=False, action="store_true", help="disable checking if the challenge file is hosted correctly before telling the CA")
    parser.add_argument("--directory-url", default=DEFAULT_DIRECTORY_URL, help="certificate authority directory url, default is Let's Encrypt")
    parser.add_argument("--ca", default=DEFAULT_CA, help="DEPRECATED! USE --directory-url INSTEAD!")
    parser.add_argument("--contact", metavar="CONTACT", default=None, nargs="*", help="Contact details (e.g. mailto:aaa@bbb.com) for your account-key")

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)

    if not os.path.isfile(CONF):
        LOGGER.error("Config file {} does not exist".format(CONF))
        sys.exit(1)

    signed_crt = get_crt(args.account_key, args.csr, args.dns_zone, log=LOGGER, CA=args.ca, disable_check=args.disable_check, directory_url=args.directory_url, contact=args.contact)
    sys.stdout.write(signed_crt)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
