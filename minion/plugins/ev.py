# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import urlparse
import OpenSSL
import socket
import struct
from pyasn1.codec.ber import decoder
from pyasn1_modules import rfc2459

from minion.plugins.base import BlockingPlugin

# http://www.mozilla.org/projects/security/certs/included/
# EV Policy OID != "Not EV"
# duplicates remove
EV_OIDS = [
  "1.2.276.0.44.1.1.1.4",
  "1.2.392.200091.100.721.1",
  "1.2.40.0.17.1.22",
  "1.2.616.1.113527.2.5.1.1",
  "1.3.6.1.4.1.14370.1.6",
  "1.3.6.1.4.1.14777.6.1.1",
  "1.3.6.1.4.1.14777.6.1.2",
  "1.3.6.1.4.1.17326.10.14.2.1.2",
  "1.3.6.1.4.1.17326.10.8.12.1.2",
  "1.3.6.1.4.1.22234.2.5.2.3.1",
  "1.3.6.1.4.1.23223.1.1.1",
  "1.3.6.1.4.1.29836.1.10",
  "1.3.6.1.4.1.34697.2.1",
  "1.3.6.1.4.1.34697.2.2",
  "1.3.6.1.4.1.34697.2.3",
  "1.3.6.1.4.1.34697.2.4",
  "1.3.6.1.4.1.40869.1.1.22.3",
  "1.3.6.1.4.1.4146.1.1",
  "1.3.6.1.4.1.4788.2.202.1",
  "1.3.6.1.4.1.6334.1.100.1",
  "1.3.6.1.4.1.6449.1.2.1.5.1",
  "1.3.6.1.4.1.782.1.2.1.8.1",
  "1.3.6.1.4.1.7879.13.24.1",
  "1.3.6.1.4.1.8024.0.2.100.1.2",
  "2.16.578.1.26.1.3.3",
  "2.16.756.1.83.21.0",
  "2.16.756.1.89.1.2.1.1",
  "2.16.792.3.0.3.1.1.5",
  "2.16.840.1.113733.1.7.23.6",
  "2.16.840.1.113733.1.7.48.1",
  "2.16.840.1.114028.10.1.2",
  "2.16.840.1.114404.1.1.2.4.1",
  "2.16.840.1.114412.2.1",
  "2.16.840.1.114413.1.7.23.3",
  "2.16.840.1.114414.1.7.23.3",
]

def hasEvOid(cert):
  for i in xrange(cert.get_extension_count()):
    ext = cert.get_extension(i)
    
    if ext.get_short_name() == "certificatePolicies":
      data = decoder.decode(ext.get_data(), asn1Spec=rfc2459.CertificatePolicies())
       
      # (CertificatePolicy(
      #                   PolicyInformation(
      #                                     CertPolicyId(value), ...)
      #                   , ...)
      # , ...)
      # http://pyasn1.sourceforge.net/rfc2459.html
      certPolicyId = data[0].getComponentByPosition(0).getComponentByPosition(0)
      return certPolicyId.prettyPrint() in EV_OIDS

  return False

class EVPlugin(BlockingPlugin):
    PLUGIN_NAME = "EV Certificate Check"
    PLUGIN_VERSION = "0.1"
    PLUGIN_WEIGHT = "light"

    FURTHER_INFO = [ {"URL": "http://en.wikipedia.org/wiki/Extended_Validation_Certificate",
                      "Title": "Wikipedia - Extended Validation Certificate"} ]

    def do_run(self):
        issues = []
        url = urlparse.urlparse(self.configuration['target'])
        host = url.hostname
        port = url.port or 443

        if not host:
          issues.append(
              {'Summary': "No hostname provided",
               'Description': "There was an error parsing the scan target argument.",
               'Severity': "Info",
               "URLs": [ {"URL": None, "Extra": None} ],
               "FurtherInfo": None})
          return self.report_issues(issues)
          
        if url.scheme != "https":
          issues.append(
              {'Summary': "Non-HTTPS target supplied",
               'Description': "This plugin is designed to test SSL certificates and may not work properly on a HTTP -> HTTPS redirect.",
               'Severity': "Info",
               "URLs": [ {"URL": None, "Extra": None} ],
               "FurtherInfo": None})
          
        try:
          # Prefer TLS
          context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)

          s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          s.settimeout(5)

          connection = OpenSSL.SSL.Connection(context,s)
          connection.connect((host, port))
          connection.setblocking(1)

          # override default timeout (30) with 3 second timeout
          tv = struct.pack('LL', 3, 0)
          connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, tv)

          connection.set_connect_state()
          connection.do_handshake()

          if not hasEvOid(connection.get_peer_certificate()):
            issues.append(
                {'Summary': "Site does not use an Extended Validation certificate",
                 'Description': "The site doesn't use an EV certificate.",
                 'Severity': "High",
                 "URLs": [ {"URL": None, "Extra": None} ],
                 "FurtherInfo": self.FURTHER_INFO})
          else:
            issues.append(
                {'Summary': "Site uses an Extended Validation certificate",
                 'Description': "The site uses an EV certificate",
                 'Severity': "Info",
                 "URLs": [ {"URL": None, "Extra": None} ],
                 "FurtherInfo": self.FURTHER_INFO})
        except OpenSSL.SSL.Error:
          issues.append(
              {'Summary': "There was an error completing a SSL connection to the site",
               'Description': "Retry the test. If the problem persists, please contact the system administrator.",
               'Severity': "Info",
               "URLs": [ {"URL": None, "Extra": None} ],
               "FurtherInfo": None})
        except:
          issues.append(
              {'Summary': "There was an unknown error connecting to the site",
               'Description': "Retry the test. If the problem persists, please contact the system administrator.",
               'Severity': "Info",
               "URLs": [ {"URL": None, "Extra": None} ],
               "FurtherInfo": None})
        finally:
          connection.close()

        return self.report_issues(issues)
