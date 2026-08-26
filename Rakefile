require 'rake/testtask'

Rake::TestTask.new(:test) do |t|
  t.libs << 'lib' << 'test'
  t.test_files = FileList['test/**/*_test.rb']
  t.warning = true
end

desc 'Regenerate the audit check catalogue in README.md'
task :catalog do
  $LOAD_PATH.unshift File.expand_path('lib', __dir__)
  require 'tasks/catalog'

  if UiManage::Catalog.update
    puts 'README.md catalogue updated.'
  else
    puts 'README.md catalogue already up to date.'
  end
end

task default: :test
