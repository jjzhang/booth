import string

from clientenv import ClientTestEnvironment

class ClientConfigTests(ClientTestEnvironment):
    mode = 'client'

    def test_site_buffer_overflow(self):
        # https://bugzilla.novell.com/show_bug.cgi?id=750256
        longfile = (string.lowercase * 3)[:63]
        expected_error = "'%s' exceeds maximum site name length" % longfile
        args = [ 'grant', '-s', longfile, '-t', 'ticket' ]
        self._test_buffer_overflow(expected_error, args=args)

    def test_ticket_buffer_overflow(self):
        # https://bugzilla.novell.com/show_bug.cgi?id=750256
        longfile = (string.lowercase * 3)[:63]
        expected_error = "'%s' exceeds maximum ticket name length" % longfile
        args = [ 'grant', '-s', 'site', '-t', longfile ]
        self._test_buffer_overflow(expected_error, args=args)
