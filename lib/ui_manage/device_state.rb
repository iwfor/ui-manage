module UiManage
  # UniFi reports device state as an integer. Shared by the views and the
  # audit checks so both name the same number the same way.
  module DeviceState
    NAMES = {
      0 => 'disconnected', 1 => 'connected', 2 => 'pending adoption',
      4 => 'updating', 5 => 'provisioning', 6 => 'unreachable',
      7 => 'adopting', 9 => 'adoption failed', 11 => 'isolated'
    }.freeze

    CONNECTED = 1

    module_function

    def label(device) = NAMES[code(device)] || "state #{code(device)}"

    def code(device) = device['state'].to_i

    def connected?(device) = code(device) == CONNECTED
  end
end
