module UiManage
  module Audit
    module Checks
      # Whether this tool verifies the controller's TLS certificate.
      #
      # Unlike the other checks this one is about the client side, but it
      # belongs in the audit: an unverified connection means every credential
      # and every answer in this report could have come from someone in the
      # middle.
      class ControllerTls < Check
        id          :controller_tls
        title       'Controller TLS certificate not verified'
        category    :security
        severity    :medium
        requires    []
        remediation 'Install a certificate your system trusts on the controller, then ' \
                    're-run `ui-manage login --verify-ssl` for this device.'

        def run
          # nil means the device predates the setting being recorded; false is
          # a deliberate "off". Both connect without verification.
          return if policy(:verify_ssl)

          finding(
            message:  'This device is configured without TLS certificate verification, so ' \
                      'the connection carrying these results is not authenticated.',
            evidence: { 'verify_ssl' => false }
          )
        end
      end
    end
  end
end
