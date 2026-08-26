module UiManage
  # Reading administrator accounts, whose shape varies more than most across
  # Network application versions.
  module AdminAccount
    # Which field carries two-factor state depends on the version, and some
    # versions report none at all.
    TOTP_KEYS = %w[x_has_totp has_totp totp_enabled x_totp_secret].freeze

    module_function

    # :yes, :no, or :unknown. Unknown is a real answer — an audit must never
    # read a field the controller does not report as "no 2FA configured".
    def two_factor(admin)
      key = TOTP_KEYS.find { |k| admin.key?(k) }
      return :unknown unless key

      value = admin[key]
      value.nil? || value == false || value == '' ? :no : :yes
    end

    # True when the controller reports 2FA state for at least one account.
    # A check has nothing to judge when it reports it for none.
    def reports_two_factor?(admins)
      Array(admins).any? { |a| two_factor(a) != :unknown }
    end

    def super?(admin)
      admin['is_super'] || admin['role'].to_s.casecmp?('super')
    end

    def name(admin) = admin['name'] || admin['email'] || admin['_id']
  end
end
