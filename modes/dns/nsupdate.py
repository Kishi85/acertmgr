#!/usr/bin/env python
# -*- coding: utf-8 -*-
# dns.nsupdate - rfc2136 based challenge handler
# Copyright (c) Rudolf Mayerhofer, 2018-2019
# available under the ISC license, see LICENSE
import re
import time

import dns.query
import dns.tsigkeyring
import dns.update

from modes.abstract import AbstractChallengeHandler


class ChallengeHandler(AbstractChallengeHandler):
    @staticmethod
    def _read_tsigkey(tsig_key_file, key_name):
        try:
            key_file = open(tsig_key_file)
            key_struct = key_file.read()
            key_file.close()
        except IOError as exc:
            raise Exception(
                "A problem was encountered opening your keyfile, %s." % tsig_key_file) from exc

        try:
            key_data = re.search(r"key \"%s\" \{(.*?)\}\;" % key_name, key_struct, re.DOTALL).group(1)
            algorithm = re.search(r"algorithm ([a-zA-Z0-9_-]+?)\;", key_data, re.DOTALL).group(1)
            tsig_secret = re.search(r"secret \"(.*?)\"", key_data, re.DOTALL).group(1)
        except AttributeError as exc:
            raise Exception(
                "Unable to decipher the keyname and secret from your key file.") from exc

        keyring = dns.tsigkeyring.from_text({
            key_name: tsig_secret
        })

        if not algorithm:
            algorithm = "HMAC-MD5.SIG-ALG.REG.INT"

        return keyring, algorithm

    @staticmethod
    def _get_soa(domain, nameserver=None):
        if nameserver:
            nameservers = [nameserver]
        else:
            nameservers = dns.resolver.get_default_resolver().nameservers

        domain = dns.name.from_text(domain)
        if not domain.is_absolute():
            domain = domain.concatenate(dns.name.root)

        while domain.parent() != dns.name.root:
            request = dns.message.make_query(domain, dns.rdatatype.SOA)
            for nameserver in nameservers:
                try:
                    response = dns.query.udp(request, nameserver)
                    if response.rcode() == dns.rcode.NOERROR:
                        answer = response.answer[0]
                        zone = answer.to_text()
                        authoritative_ns = answer.items[0].mname.to_text()
                        return zone, authoritative_ns
                    else:
                        break
                except dns.exception.Timeout:
                    # Go to next nameserver on timeout
                    continue
                except dns.exception.DNSException:
                    # Break loop on any other error
                    break
            domain = domain.parent()
        raise Exception('Could not find Zone SOA for "{0}"'.format(domain))

    @staticmethod
    def get_challenge_type(self):
        return "dns-01"

    def __init__(self, config):
        AbstractChallengeHandler.__init__(self, config)
        if 'nsupdate_keyfile' in config:
            self.keyring, self.keyalgorithm = self._read_tsigkey(config.get("nsupdate_keyfile"),
                                                                 config.get("nsupdate_keyname"))
        else:
            self.keyring = dns.tsigkeyring.from_text({
                config.get("nsupdate_keyname"): config.get("nsupdate_keyvalue")
            })
            self.keyalgorithm = config.get("nsupdate_keyalgorithm", "HMAC-MD5.SIG-ALG.REG.INT")
        self.dns_server = config.get("nsupdate_server")
        self.dns_ttl = int(config.get("nsupdate_ttl", "60"))
        self.dns_updatedomain = config.get("nsupdate_updatedomain")

    def _determine_challenge_domain(self, domain):
        if self.dns_updatedomain:
            return self.dns_updatedomain
        else:
            return "_acme-challenge.{0}".format(domain)

    def create_challenge(self, domain, thumbprint, token):
        domain = self._determine_challenge_domain(domain)
        nameserver = self.dns_server
        if nameserver:
            zone, _ = self._get_soa(domain, nameserver)
        else:
            zone, nameserver = self._get_soa(domain)

        update = dns.update.Update(zone, keyring=self.keyring, keyalgorithm=self.keyalgorithm)
        update.add(domain, self.dns_ttl, 'TXT', token)
        dns.query.tcp(update, nameserver)
        # Delay the challenge creation to allow dns changes to propagate
        time.sleep(2 * self.dns_ttl)

    def destroy_challenge(self, domain, thumbprint, token):
        domain = self._determine_challenge_domain(domain)
        nameserver = self.dns_server
        if nameserver:
            zone, _ = self._get_soa(domain, nameserver)
        else:
            zone, nameserver = self._get_soa(domain)
        update = dns.update.Update(zone, keyring=self.keyring, keyalgorithm=self.keyalgorithm)
        update.delete(domain, self.dns_ttl, 'TXT', token)
        dns.query.tcp(update, nameserver)
