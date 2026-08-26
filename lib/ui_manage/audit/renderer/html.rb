require 'cgi'

module UiManage
  module Audit
    class Renderer
      # A single self-contained page, for handing the result to someone who
      # will not be reading a terminal. No external assets, so it works from a
      # file:// URL or an email attachment.
      class Html < Renderer
        SEVERITY_HUE = {
          'critical' => '0, 72%', 'high' => '18, 78%', 'medium' => '38, 82%',
          'low' => '198, 62%', 'info' => '220, 8%'
        }.freeze

        def render
          <<~HTML
            <!doctype html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Network audit</title>
            <style>#{style}</style>
            </head>
            <body>
            <main>
              <h1>Network audit</h1>
              #{summary_block}
              #{findings_blocks unless summary_only? || findings.empty?}
              #{resolved_block if resolved.any?}
              #{not_checked_block if report.skipped.any? || report.errored.any?}
            </main>
            </body>
            </html>
          HTML
        end

        private

        def h(text) = CGI.escapeHTML(text.to_s)

        def style
          <<~CSS
            :root { --bg: #fdfdfc; --fg: #1c1c1a; --muted: #6b6b66; --line: #e2e2dd; --card: #fff; }
            @media (prefers-color-scheme: dark) {
              :root { --bg: #16161a; --fg: #e8e8e4; --muted: #9a9a94; --line: #2c2c32; --card: #1e1e23; }
            }
            * { box-sizing: border-box; }
            body { margin: 0; background: var(--bg); color: var(--fg);
                   font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, sans-serif; }
            main { max-width: 60rem; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }
            h1 { font-size: 1.7rem; margin: 0 0 1.5rem; letter-spacing: -0.02em; }
            h2 { font-size: 1.1rem; margin: 2.5rem 0 0.75rem; letter-spacing: -0.01em; }
            .tally { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0 0 1.5rem; }
            .pill { padding: 0.2rem 0.7rem; border-radius: 999px; font-size: 0.8rem;
                    font-weight: 600; border: 1px solid var(--line); }
            .pill[data-sev] { background: hsl(var(--hue), 92%); color: hsl(var(--hue), 28%);
                              border-color: hsl(var(--hue), 82%); }
            @media (prefers-color-scheme: dark) {
              .pill[data-sev] { background: hsl(var(--hue), 18%); color: hsl(var(--hue), 78%);
                                border-color: hsl(var(--hue), 30%); }
            }
            table { border-collapse: collapse; width: 100%; margin: 0 0 1rem; font-size: 0.9rem; }
            td { padding: 0.35rem 0.75rem 0.35rem 0; border-bottom: 1px solid var(--line); }
            td:last-child { text-align: right; font-variant-numeric: tabular-nums; }
            .finding { background: var(--card); border: 1px solid var(--line);
                       border-left: 3px solid hsl(var(--hue), 55%); border-radius: 6px;
                       padding: 0.9rem 1.1rem; margin: 0 0 0.6rem; }
            .finding p { margin: 0 0 0.4rem; font-weight: 550; }
            .meta { color: var(--muted); font-size: 0.82rem; margin: 0; }
            .meta code { font-size: 0.82rem; }
            .note { color: var(--muted); font-size: 0.9rem; margin: 0 0 0.75rem; }
            ul { margin: 0; padding-left: 1.1rem; color: var(--muted); font-size: 0.9rem; }
            li { margin: 0.2rem 0; }
          CSS
        end

        def summary_block
          s = summary
          rows = [['Checks run', s['checks']], ['Passed', s['passed']],
                  ['With findings', s['failed']], ['Not checked', s['skipped']],
                  ['Errored', s['errored']]]
          rows << ['Suppressed', s['suppressed']] if s['suppressed'].positive?

          pills = counts.map do |severity, n|
            %(<span class="pill" data-sev style="--hue: #{SEVERITY_HUE.fetch(severity, '220, 8%')}">#{n} #{h(severity)}</span>)
          end.join
          pills = %(<span class="pill">No findings</span>) if counts.empty?

          %(<div class="tally">#{pills}</div>\n<table>) +
            rows.map { |label, value| "<tr><td>#{h(label)}</td><td>#{value}</td></tr>" }.join +
            '</table>'
        end

        def findings_blocks
          findings.group_by(&:severity).map do |severity, group|
            hue   = SEVERITY_HUE.fetch(severity.to_s, '220, 8%')
            cards = group.map { |finding| finding_card(finding, hue) }.join
            %(<h2>#{h(severity.to_s.capitalize)} (#{group.size})</h2>#{cards})
          end.join
        end

        def finding_card(finding, hue)
          meta = ["check <code>#{h(finding.check_id)}</code>"]
          meta << "subject <code>#{h(subject_of(finding))}</code>" unless finding.subject.nil?
          fix  = remediate? && finding.remediation ? %(<p class="meta">Fix: #{h(finding.remediation)}</p>) : ''

          %(<div class="finding" style="--hue: #{hue}"><p>#{h(scrub(finding.message))}</p>) +
            %(<p class="meta">#{meta.join(' · ')}</p>#{fix}</div>)
        end

        # Its own section, with the distinction spelled out — a reader
        # skimming a report must not take these for passes.
        def not_checked_block
          items = report.skipped.map { |r| "<li><code>#{h(r.check.id)}</code> — #{h(r.reason)}</li>" } +
                  report.errored.map { |r| "<li><code>#{h(r.check.id)}</code> — <strong>errored</strong>: #{h(r.reason)}</li>" }

          %(<h2>Not checked</h2><p class="note">These checks could not run. They are not passes.</p>) +
            "<ul>#{items.join}</ul>"
        end

        def resolved_block
          %(<h2>Resolved since the baseline</h2><ul>) +
            resolved.map { |key| "<li><code>#{h(key)}</code></li>" }.join + '</ul>'
        end
      end
    end
  end
end
