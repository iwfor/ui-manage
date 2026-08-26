module UiManage
  module Audit
    module Checks
      # How many accounts hold full control. Every one of them is a way in
      # that bypasses everything else, so the count is worth keeping small
      # deliberately rather than by accident.
      class AdminSuperCount < Check
        id          :admin_super_count
        title       'More super administrators than the configured maximum'
        category    :security
        severity    :medium
        requires    :admins
        remediation 'UniFi Network > Settings > Admins: reduce the accounts holding ' \
                    'full site control, or raise max_super_admins in audit.toml if ' \
                    'this many is deliberate.'

        def run
          limit  = threshold('max_super_admins')
          supers = data(:admins).select { |a| AdminAccount.super?(a) }
          return if supers.size <= limit

          finding(
            message:  "#{supers.size} accounts hold super administrator rights, above the " \
                      "configured maximum of #{limit}.",
            evidence: { 'count' => supers.size, 'maximum' => limit,
                        'admins' => supers.map { |a| AdminAccount.name(a) } }
          )
        end
      end
    end
  end
end
