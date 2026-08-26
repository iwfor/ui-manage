module UiManage
  module Audit
    module Checks
      # Administrators without a second factor. A controller admin can rewrite
      # the firewall, so a reused password is the whole perimeter.
      class AdminTwoFactor < Check
        id          :admin_two_factor
        title       'Administrator without two-factor authentication'
        category    :security
        severity    :high
        requires    :admins
        remediation 'UniFi account settings > Security > Two-Factor Authentication, ' \
                    'per administrator.'

        def run
          admins = data(:admins)

          # Some versions report no 2FA state at all. Judging that as "nobody
          # has 2FA" would be a fabricated finding; judging it as "everyone
          # does" would be worse.
          unless AdminAccount.reports_two_factor?(admins)
            skip!('this controller does not report two-factor state for any administrator')
          end

          admins.each do |admin|
            case AdminAccount.two_factor(admin)
            when :no
              finding(
                subject:  AdminAccount.name(admin),
                severity: AdminAccount.super?(admin) ? :critical : :high,
                message:  "#{AdminAccount.name(admin)} has no second factor configured" \
                          "#{AdminAccount.super?(admin) ? ' and is a super administrator' : ''}.",
                evidence: { 'super' => !!AdminAccount.super?(admin) }
              )
            when :unknown
              finding(
                subject:  AdminAccount.name(admin),
                severity: :info,
                message:  "#{AdminAccount.name(admin)}'s two-factor state is not reported by this controller.",
                evidence: { 'two_factor' => 'unknown' }
              )
            end
          end
        end
      end
    end
  end
end
