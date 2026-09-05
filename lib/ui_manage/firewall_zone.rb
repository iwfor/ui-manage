module UiManage
  # Reads the zone-based firewall's zones (Network 9 and later).
  #
  # Shared by the `vlans` view, the guest-network audit check, and the
  # management commands, so all three agree on which zone a network sits in
  # and which zone counts as guest treatment.
  module FirewallZone
    # The zone whose networks reach the internet and nothing internal — what
    # a guest network is on a zone-based controller.
    GUEST_KEY = 'hotspot'.freeze

    module_function

    # network id => zone record, for every network any zone lists.
    def by_network(zones)
      Array(zones).each_with_object({}) do |zone, index|
        Array(zone['network_ids']).each { |id| index[id] = zone }
      end
    end

    def guest?(zone) = zone && zone['zone_key'].to_s == GUEST_KEY

    # The zone named by a key ("hotspot") or display name ("Hotspot").
    def find(zones, name)
      Array(zones).find { |z| z['zone_key'].to_s.casecmp?(name.to_s) || z['name'].to_s.casecmp?(name.to_s) }
    end
  end
end
