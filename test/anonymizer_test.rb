require_relative 'test_helper'

module UiManage
  class AnonymizerTest < TestCase
    def anon = @anon ||= Anonymizer.new(true)

    # --- addresses ---------------------------------------------------------

    def test_addresses_map_to_documentation_ranges
      assert_match(/\A(192\.0\.2|198\.51\.100|203\.0\.113)\./, anon.ip('192.168.1.50'))
    end

    def test_macs_map_to_a_locally_administered_prefix
      assert_match(/\A02:00:00:/, anon.mac('aa:bb:cc:dd:ee:ff'))
    end

    def test_wildcard_addresses_are_left_recognisable
      %w[0.0.0.0 0.0.0.0/0 255.255.255.255].each { |w| assert_equal w, anon.ip(w) }
    end

    def test_the_same_value_always_maps_to_the_same_placeholder
      assert_equal anon.ip('10.0.0.1'), anon.ip('10.0.0.1')
      refute_equal anon.ip('10.0.0.1'), anon.ip('10.0.0.2')
    end

    # --- names -------------------------------------------------------------

    # An SSID has no recognisable shape, so it cannot be caught by scanning
    # text — it has to be replaced where the field is read.
    def test_names_are_replaced_by_kind
      assert_equal 'Network-1', anon.ssid('SmithFamily')
      assert_equal 'Device-2',  anon.device_name('AP-Garage')
      assert_equal 'Person-3',  anon.person('alice')
      assert_equal 'person4@example.com', anon.email('alice@example.com')
    end

    def test_one_original_maps_to_one_placeholder_across_kinds
      first = anon.ssid('Shared')

      assert_equal first, anon.label('Shared')
      assert_equal first, anon.device_name('Shared')
    end

    # A finding that names an SSID must be anonymised the same way as the
    # column that named it.
    def test_a_registered_name_is_replaced_wherever_it_appears_in_text
      anon.ssid('SmithFamily')

      assert_equal 'Network-1 uses no encryption.', anon.scrub('SmithFamily uses no encryption.')
    end

    def test_names_and_addresses_are_replaced_in_the_same_pass
      anon.device_name('AP-Garage')
      scrubbed = anon.scrub('AP-Garage at 192.168.1.5 (aa:bb:cc:dd:ee:ff) is down')

      refute_includes scrubbed, 'AP-Garage'
      refute_includes scrubbed, '192.168.1.5'
      refute_includes scrubbed, 'aa:bb:cc:dd:ee:ff'
    end

    # Replacing the shorter name first would corrupt the longer one.
    def test_a_name_containing_another_name_is_replaced_whole
      short = anon.ssid('Home')
      long  = anon.ssid('HomeGuest')

      assert_equal long, anon.scrub('HomeGuest')
      assert_equal short, anon.scrub('Home')
    end

    def test_blank_names_are_left_alone
      assert_nil anon.ssid(nil)
      assert_equal '', anon.ssid('')
    end

    # --- disabled ----------------------------------------------------------

    def test_everything_passes_through_when_disabled
      off = Anonymizer.new(false)

      assert_equal 'SmithFamily', off.ssid('SmithFamily')
      assert_equal '192.168.1.1', off.ip('192.168.1.1')
      assert_equal 'AP-Garage at 192.168.1.1', off.scrub('AP-Garage at 192.168.1.1')
    end

    # --- structures --------------------------------------------------------

    def test_deep_scrub_walks_nested_structures
      anon.ssid('Guest')
      scrubbed = anon.deep_scrub('wlans' => [{ 'name' => 'Guest', 'ip' => '10.0.0.1', 'vlan' => 30 }])

      assert_equal 'Network-1', scrubbed['wlans'][0]['name']
      refute_equal '10.0.0.1',  scrubbed['wlans'][0]['ip']
      assert_equal 30,          scrubbed['wlans'][0]['vlan']
    end
  end

  class CatalogTest < TestCase
    # The README table is generated. If this fails, run `rake catalog`.
    def test_the_readme_check_catalog_is_up_to_date
      require 'tasks/catalog'
      readme = File.expand_path('../README.md', __dir__)

      assert Catalog.current?(readme),
             'README check catalog is stale — run `rake catalog` to regenerate it.'
    end

    def test_the_catalog_covers_every_registered_check
      require 'tasks/catalog'
      markdown = Catalog.markdown

      Audit::Registry.all.each do |check|
        assert_includes markdown, "`#{check.id}`", "#{check.id} is missing from the catalog"
      end
    end
  end

  class CompletionsTest < TestCase
    def script(values: {})
      Completions.generate('bash', prog: 'ui-manage',
                                   commands: { 'audit' => %w[--check --severity] },
                                   values: values)
    end

    def test_an_unsupported_shell_is_rejected
      assert_raises(ArgumentError) { Completions.generate('fish', prog: 'x', commands: {}) }
    end

    def test_zsh_reuses_the_bash_script
      zsh = Completions.generate('zsh', prog: 'ui-manage', commands: {})

      assert_includes zsh, 'bashcompinit'
    end

    def test_flags_with_known_values_complete_them
      out = script(values: { '--severity' => %i[high low] })

      assert_includes out, '--severity)'
      assert_includes out, 'high low'
    end

    def test_a_script_without_value_flags_has_no_empty_case
      refute_includes script, 'case "$prev" in'
    end

    def test_the_generated_script_is_valid_bash
      require 'open3'
      _, err, status = Open3.capture3('bash', '-n', stdin_data: script(values: { '--check' => %w[a b] }))

      assert status.success?, "generated completion script is not valid bash: #{err}"
    end
  end
end
