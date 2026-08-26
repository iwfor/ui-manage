module UiManage
  module Audit
    module Checks
      # Storage filling up on the controller. When it runs out, the controller
      # stops recording statistics and can fail to take backups — quietly, and
      # usually noticed only when a backup is needed.
      class DeviceStorage < Check
        id          :device_storage
        title       'Controller storage above threshold'
        category    :health
        severity    :high
        requires    :devices
        remediation 'Settings > System > Maintenance: reduce data retention, or clear ' \
                    'old backups. Adjust the bar with storage_percent in audit.toml.'

        def run
          limit  = threshold('storage_percent')
          disks  = Array(gateway&.dig('storage'))
          skip!('this device does not report storage information') if disks.empty?

          disks.each do |disk|
            size = disk['size'].to_i
            used = disk['used'].to_i
            next if size.zero?

            percent = used.to_f / size * 100
            next if percent <= limit

            name = disk['name'] || disk['mount_point'] || 'storage'
            finding(
              subject:  name,
              message:  "#{name} is #{percent.round(1)}% full " \
                        "(#{Formatter.bytes_human(size - used)} free), above the #{limit}% threshold.",
              evidence: { 'percent' => percent.round(1), 'threshold' => limit,
                          'mount' => disk['mount_point'] }
            )
          end
        end
      end
    end
  end
end
