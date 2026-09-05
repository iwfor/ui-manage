module UiManage
  # Reading administrator accounts, whose shape varies more than most across
  # Network application versions. The current source, /api/stat/admin, lists
  # every administrator on the controller with a `roles` entry per site.
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

    # Whether the account can administer +site+. Super administrators can
    # administer every site; a record that carries no site roles at all is
    # taken as listed for this site, since the controller gave nothing to
    # say otherwise.
    def member_of?(admin, site)
      return true if super?(admin) || !admin.key?('roles')

      Array(admin['roles']).any? { |r| r['site_name'] == site }
    end

    # The account's role on +site+: an explicit `role`, else the site's entry
    # in `roles`, else 'super' for a super administrator with no site entry.
    def role(admin, site: nil)
      admin['role'] ||
        Array(admin['roles']).find { |r| r['site_name'] == site }&.dig('role') ||
        (super?(admin) ? 'super' : nil)
    end

    def name(admin) = admin['name'] || admin['email'] || admin['_id']
  end
end
