import ldap
from openerp.osv import osv


class CompanyLDAP(osv.osv):
    _inherit = "res.company.ldap"

    def connect(self, conf):
        """
        Connect to an LDAP server specified by an ldap
        configuration dictionary.
        :param dict conf: LDAP configuration
        :return: an LDAP object
        """
        prefix = (
            ""
            if conf["ldap_server"].startswith("ldap://")
            or conf["ldap_server"].startswith("ldaps://")
            else "ldap://"
        )
        uri = "%s%s:%d" % (prefix, conf["ldap_server"], conf["ldap_server_port"])

        connection = ldap.initialize(uri)
        if conf["ldap_tls"]:
            connection.start_tls_s()
        return connection
