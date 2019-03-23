#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - acme api v1 functions
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import copy
import datetime
import json
import re
import time

from acertmgr import tools
from acertmgr.authority.acme import ACMEAuthority as AbstractACMEAuthority


class ACMEAuthority(AbstractACMEAuthority):
    # @brief Init class with config
    # @param config Configuration data
    # @param key Account key data
    def __init__(self, config, key):
        AbstractACMEAuthority.__init__(self, config, key)
        self.ca = config['authority']
        self.agreement = config['authority_tos_agreement']

    # @brief create the header information for ACME communication
    # @param key the account key
    # @return the header for ACME
    def _prepare_header(self):
        numbers = self.key.public_key().public_numbers()
        header = {
            "alg": "RS256",
            "jwk": {
                "e": tools.bytes_to_base64url(tools.number_to_byte_format(numbers.e)),
                "kty": "RSA",
                "n": tools.bytes_to_base64url(tools.number_to_byte_format(numbers.n)),
            },
        }
        return header

    # @brief helper function to make signed requests
    # @param url the request URL
    # @param header the message header
    # @param payload the message
    # @return tuple of return code and request answer
    def _send_signed(self, url, header, payload):
        payload64 = tools.bytes_to_base64url(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        protected["nonce"] = tools.get_url(self.ca + "/directory").headers['Replay-Nonce']
        protected64 = tools.bytes_to_base64url(json.dumps(protected).encode('utf8'))
        out = tools.signature_of_str(self.key, '.'.join([protected64, payload64]))
        data = json.dumps({
            "header": header, "protected": protected64,
            "payload": payload64, "signature": tools.bytes_to_base64url(out),
        })
        try:
            resp = tools.get_url(url, data.encode('utf8'))
            return resp.getcode(), resp.read()
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__)()

    # @brief register an account over ACME
    # @return True if new account was registered, False otherwise
    def register_account(self):
        header = self._prepare_header()
        code, result = self._send_signed(self.ca + "/acme/new-reg", header, {
            "resource": "new-reg",
            "agreement": self.agreement,
        })
        if code == 201:
            print("Registered!")
            return True
        elif code == 409:
            print("Already registered!")
            return False
        else:
            raise ValueError("Error registering: {0} {1}".format(code, result))

    # @brief function to fetch certificate using ACME
    # @param csr the certificate signing request in pyopenssl format
    # @param domains list of domains in the certificate, first is CN
    # @param challenge_handlers a dict containing challenge for all given domains
    # @return the certificate and corresponding ca as a tuple
    # @note algorithm and parts of the code are from acme-tiny
    def get_crt_from_csr(self, csr, domains, challenge_handlers):
        header = self._prepare_header()
        account_thumbprint = tools.bytes_to_base64url(
            tools.hash_of_str(json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))))

        challenges = dict()
        tokens = dict()
        valid_times = list()
        # verify each domain
        try:
            for domain in domains:
                print("Verifying {0}...".format(domain))

                # get new challenge
                code, result = self._send_signed(self.ca + "/acme/new-authz", header, {
                    "resource": "new-authz",
                    "identifier": {"type": "dns", "value": domain},
                })
                if code != 201:
                    raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

                # create the challenge
                challenges[domain] = [c for c in json.loads(result.decode('utf8'))['challenges'] if
                                      c['type'] == challenge_handlers[domain].get_challenge_type()][0]
                tokens[domain] = re.sub(r"[^A-Za-z0-9_\-]", "_", challenges[domain]['token'])

                if domain not in challenge_handlers:
                    raise ValueError("No challenge handler given for domain: {0}".format(domain))

                valid_times.append(
                    challenge_handlers[domain].create_challenge(domain, account_thumbprint, tokens[domain]))

            print("Waiting until challenges are valid ({})".format(",".join([str(x) for x in valid_times])))
            for valid_time in valid_times:
                while datetime.datetime.now() < valid_time:
                    time.sleep(1)

            for domain in domains:
                challenge_handlers[domain].start_challenge()
                try:
                    print("Starting key authorization")
                    # notify challenge are met
                    keyauthorization = "{0}.{1}".format(tokens[domain], account_thumbprint)
                    code, result = self._send_signed(challenges[domain]['uri'], header, {
                        "resource": "challenge",
                        "keyAuthorization": keyauthorization,
                    })
                    if code != 202:
                        raise ValueError("Error triggering challenge: {0} {1}".format(code, result))

                    # wait for challenge to be verified
                    while True:
                        try:
                            resp = tools.get_url(challenges[domain]['uri'])
                            challenge_status = json.loads(resp.read().decode('utf8'))
                        except IOError as e:
                            raise ValueError("Error checking challenge: {0} {1}".format(
                                e.code, json.loads(e.read().decode('utf8'))))
                        if challenge_status['status'] == "pending":
                            time.sleep(2)
                        elif challenge_status['status'] == "valid":
                            print("{0} verified!".format(domain))
                            break
                        else:
                            raise ValueError("{0} challenge did not pass: {1}".format(
                                domain, challenge_status))
                finally:
                    challenge_handlers[domain].stop_challenge()
        finally:
            # Destroy challenge handlers in reverse order to replay
            # any saved state information in the handlers correctly
            for domain in reversed(domains):
                try:
                    challenge_handlers[domain].destroy_challenge(domain, account_thumbprint, tokens[domain])
                except Exception as e:
                    print('Challenge destruction failed: {}'.format(e))

        # get the new certificate
        print("Signing certificate...")
        code, result = self._send_signed(self.ca + "/acme/new-cert", header, {
            "resource": "new-cert",
            "csr": tools.bytes_to_base64url(tools.convert_csr_to_der_bytes(csr)),
        })
        if code != 201:
            raise ValueError("Error signing certificate: {0} {1}".format(code, result))

        # return signed certificate!
        print("Certificate signed!")
        cert = tools.convert_der_bytes_to_cert(result)
        return cert, tools.download_issuer_ca(cert)
